import * as path from 'path';
import {URL,pathToFileURL} from 'url';
import * as vscode from 'vscode';
import {readFileSync,writeFileSync} from 'fs';
import log = require('loglevel');
import * as crypto from 'crypto';
import * as JSZip from 'jszip';
import { v4 as uuidv4 } from 'uuid';
import { promises as fs } from 'fs';
import * as os from 'os';

import { ScanUpdateScanStatusEnum, ScanResourceScanStatusEnum, SegmentsApi, FindingsApi, ScanFindingsResource, addInterceptor, removeGlobalInterceptor, updateScanStatus, ScanResource, getScanStatus, Scan, createNewScan } from '../apiWrappers/pipelineAPIWrapper';
import { ConfigSettings } from '../util/configSettings';
import { CredsHandler } from '../util/credsHandler';
import { AxiosResponse } from 'axios';
import { jsonToVisualOutput, pipeline_output_display_style } from '../reports/pipelineScanJsonHandler';
import { getNested } from '../util/jsonUtil';


function getTimeStamp(): string {
    const now = new Date();
    return `${now.getHours()}:${('0'+now.getMinutes()).slice(-2)}:${('0'+now.getSeconds()).slice(-2)}_${('00'+now.getMilliseconds()).slice(-3)}`;
}

export class VeracodePipelineScanHandler {

    private outputChannel:vscode.OutputChannel;
    private pipelineStatusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);


    constructor() {
        this.outputChannel = vscode.window.createOutputChannel('Veracode Pipeline Scan');
    }

    public clear() {
        this.outputChannel.clear();
	    this.outputChannel.show();
    }


    public logMessage(message: string) {
        this.outputChannel.appendLine(`${getTimeStamp()} - ${message}`);
    }


    public async scanFileWithPipeline (target: vscode.Uri,configSettings:ConfigSettings) {
        this.logMessage('target: '+target)

        let needZip:number
        let newTarget:any
        let fileUrl:any
        let filenameToZip:string = 'empty.zip'


        const fileExt = target.fsPath.split(".")
        const lastElement = fileExt[fileExt.length - 1];

        if ( lastElement == "war" || lastElement == "jar" || lastElement == "ear" || lastElement == "apk" || lastElement == "zip"){
            needZip = 0
            console.log('File Extension: '+lastElement)
        }
        else {
            needZip = 1
            console.log('File Extension: '+lastElement)
        }

        if ( needZip == 1 ){
            async function createZipFile(sourceFilePath: string): Promise<string> {
                const zip = new JSZip();
                const sourceFileContent = await fs.readFile(sourceFilePath);

                zip.file(sourceFilePath.split('/').pop() || 'default.name', sourceFileContent);
    

                const zipFileName = path.join(os.tmpdir(), `${uuidv4()}.zip`);
                const zipContent = await zip.generateAsync({ type: 'nodebuffer' });
                await fs.writeFile(zipFileName, zipContent);
                console.log('zip file inside function: '+zipFileName)
                return zipFileName;
            }
            filenameToZip = target.fsPath.substring(0);
            console.log('filenameToZip: '+filenameToZip)
            newTarget = await createZipFile(filenameToZip)
            console.log('Zipfile: '+newTarget)
        }
        else {
            newTarget = target 
        }
        configSettings.loadSettings();
        this.clear();

        

        let credsHandler = new CredsHandler(configSettings.getCredsFile(),configSettings.getCredsProfile());
        await credsHandler.loadCredsFromFile();

        let filenameToDisplay = target.fsPath.substring(target.fsPath.lastIndexOf(path.sep) + 1);
        let filename = newTarget;
        this.logMessage('filename: '+filenameToDisplay)
        this.pipelineStatusBarItem.text = `Scanning ${filenameToDisplay}`;
        this.pipelineStatusBarItem.show();
        
        const pipelineScanResultsFilename = configSettings.getPipelineResultFilename();
        
        try {
            if ( needZip == 1 ){
                fileUrl = newTarget
            }
            else {
                fileUrl = pathToFileURL(target.fsPath);
            }
            
            if (vscode.workspace.workspaceFolders && pipelineScanResultsFilename) {
                let outputFile = pathToFileURL(path.join(vscode.workspace.workspaceFolders[0].uri.fsPath, pipelineScanResultsFilename));
                const outputStyle = configSettings.getPipelineResultOutputStyle();
                this.logMessage(`Beginning scanning of '${filename}'`)
                await runPipelineScan(credsHandler,fileUrl, outputFile,outputStyle, (messgae:string) => {this.outputChannel.appendLine(`${getTimeStamp()} - ${messgae}`)});
                this.logMessage(`Analysis Complete.`); 
                this.pipelineStatusBarItem.text = `Scan complete ${filename}`;
                setTimeout(() => {
                    this.pipelineStatusBarItem.hide();
                }, 10000);
            }
        } catch(error) {
            this.logMessage(getNested(error,'message'));
        }
    }
}

export async function runPipelineScan(credsHandler:CredsHandler, target: URL, outputFile: URL,outputStyle: pipeline_output_display_style, messageFunction: (message: string) => void = ((m:string) => log.debug(m))) {
    log.debug('runPipelineScan - START');
	
    const findingsApi = new FindingsApi();

    let runningScanId = '';

    let fileUrlString = target.toString();
    let fileName = fileUrlString.substring(fileUrlString.lastIndexOf(path.sep) + 1);
	messageFunction(`Scanning ${fileName}`);

    let file = readFileSync(target);

    const interceptor: number = addInterceptor(credsHandler);
    try {
        // Add interceptor
        // Create a scan ID
        const scanHash: Scan = createScanFileHash(file,fileName);
        let scansPostResponse = await createNewScan(scanHash);
        log.info(scansPostResponse);
        if (scansPostResponse.data.scan_id && scansPostResponse.data.binary_segments_expected) {
            runningScanId = scansPostResponse.data.scan_id;
            messageFunction(`Scan ID ${runningScanId}`);
            await uploadFile(runningScanId, file, scansPostResponse.data.binary_segments_expected,messageFunction);
            try {
                let startScanPutResponse = await updateScanStatus(runningScanId,ScanUpdateScanStatusEnum.STARTED);
                messageFunction(`Scan status ${startScanPutResponse.data.scan_status}`);
            } catch(error) {
                messageFunction(getNested(error,'message'));
            }
            await pollScanStatus(runningScanId,messageFunction);
            let scansScanIdFindingsGetResponse = await findingsApi.scansScanIdFindingsGet(runningScanId);
            if (scansScanIdFindingsGetResponse.data.findings) {
                messageFunction(`Number of findings is ${scansScanIdFindingsGetResponse.data.findings.length}`);
                processScanFindingsResource(scansScanIdFindingsGetResponse.data, outputFile);
                // Add display for the pipeline findings
                await jsonToVisualOutput(outputFile,outputStyle);
            }
        }
    } catch(error) {
        messageFunction(getNested(error,'message'));
    }
    removeGlobalInterceptor(interceptor);
}

async function cancelScan(scanId: string,messageCallback?: (message: string) => void) {
    if (messageCallback) {
        messageCallback(`Cancelling scan ${scanId}`);
    }
	try {
        let scansScanIdPutResponse:AxiosResponse<ScanResource> = await updateScanStatus(scanId, ScanUpdateScanStatusEnum.CANCELLED);
        if (messageCallback){
            messageCallback(`Scan status ${scansScanIdPutResponse.data.scan_status}`);
        }
    } catch(error) {
        if (messageCallback) {
            messageCallback(getNested(error,'message'));
        }
    }
}

function createScanFileHash(file: Buffer, fileName: string): Scan {
	return {
		binary_hash: crypto.createHash('sha256').update(file).digest('hex'),
		binary_name: fileName,
		binary_size: file.byteLength
	};
}

async function uploadFile(scanId: string, file: Buffer, segmentCount: number,messageFunction: (message: string) => void = ((m:string) => {return;})) {
    const segmentsApi = new SegmentsApi();
	for (let i = 0; i < segmentCount; i++) {
		let segmentBegin = i * (file.byteLength/segmentCount);
		let segmentEnd = 0;
		if (i === segmentCount - 1) {
			segmentEnd = file.byteLength;
		} else {
			segmentEnd = segmentBegin + file.byteLength/segmentCount;
		}
		let fileSegment = file.slice(segmentBegin, segmentEnd);
		try {
			let scansScanIdSegmentsSegmentIdPutResponse = await segmentsApi.scansScanIdSegmentsSegmentIdPut(scanId, i, fileSegment);
			messageFunction(`Uploaded segment ${i+1} out of ${segmentCount} of total upload size: ${scansScanIdSegmentsSegmentIdPutResponse.data.segment_size} bytes`);
		} catch(error) {
			messageFunction(getNested(error,'message'));
		}
	}
}

async function pollScanStatus(scanId: string,messageFunction: (message: string) => void = ((m:string) => {return;})) {
	let scanComplete = false;
    let scansScanIdGetResponse;
	while (!scanComplete) {
		await sleep(4000);
        scansScanIdGetResponse = await getScanStatus(scanId);
		switch(scansScanIdGetResponse.data.scan_status) {
			case ScanResourceScanStatusEnum.PENDING:
			case ScanResourceScanStatusEnum.STARTED:
			case ScanResourceScanStatusEnum.UPLOADING: {
				break;
			}
			default: {
				scanComplete = true;
			}
		}
		messageFunction(`Scan status ${scansScanIdGetResponse.data.scan_status}`);
	}
}

function processScanFindingsResource(scanFindingsResource: ScanFindingsResource, outputFile: URL,messageFunction: (message: string) => void = ((m:string) => {return;})) {
    messageFunction(`Saving results to ${outputFile.toString()}`);
    let data = JSON.stringify(scanFindingsResource, null, 4);
    writeFileSync(outputFile, data);
}

// Utils functions

function sleep(ms: number) {
	return new Promise((resolve) => {
	  	setTimeout(resolve, ms);
	});
}



