import {APIHandler} from '../util/apiQueryHandler';
import { CredsHandler } from '../util/credsHandler';
import { ProxySettings } from '../util/proxyHandler';
import { ProjectConfigHandler } from '../util/projectConfigHandler';

import log from 'loglevel';
import { VeracodeNode, NodeType } from '../models/dataTypes';

const findingsRequest = async (credentialHandler:CredsHandler, proxySettings: ProxySettings|null,appGUID:string,sandboxGUID:string|null,flawPullSize: number,scanType: string[]|undefined) => {
    log.debug('findingsRequest - START');
    let findings:any  = {};
    let path = `/appsec/v2/applications/${appGUID}/findings`;
    let params:any = { "size": flawPullSize};

    let projectConfig = new ProjectConfigHandler
    await projectConfig.loadProjectConfigFromFile();
    const API_HOST = projectConfig.getRegion()
    console.log('API_HOST_findingsAPIWrapper: '+API_HOST)


    

    if (sandboxGUID) {
        params.context = sandboxGUID;
    }
    if (scanType) {
        params.scan_type = scanType.toString();
    }

    try {
        findings = await APIHandler.request(
            API_HOST,
            path,
            params,
            'get',
            undefined,
            credentialHandler,  
            proxySettings  
        );
        console.log("Finished Findings API request");
        console.log(findings.data);
        
    } catch (error) {
        if (error instanceof Error) {
            log.error(error.message);
        }
        findings = {};
    }
    console.log('end Findings request');
    log.debug('findingsRequest - END');
    return findings;
}

export const getSandboxFindings = async (sandboxNode: VeracodeNode,credentialHandler:CredsHandler, proxySettings: ProxySettings|null,flawPullSize:number, scanType: string[]|undefined): Promise<VeracodeNode[]> => {
    const sandboxGUID = sandboxNode.type === NodeType.Sandbox ? sandboxNode.id : null;
    const findings: any = await findingsRequest(credentialHandler,proxySettings,sandboxNode.parent,sandboxGUID,flawPullSize,scanType);
    return findings.data || {};
}


