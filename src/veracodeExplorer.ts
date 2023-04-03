'use strict';



import * as vscode from 'vscode';
import log = require('loglevel');
import glob = require('glob');
import { convert } from 'html-to-text';
import { getNested } from './util/jsonUtil';

import { ConfigSettings } from "./util/configSettings";
import { CredsHandler } from "./util/credsHandler";
import { ProjectConfigHandler } from "./util/projectConfigHandler";
import { ProxyHandler } from "./util/proxyHandler";
import { VeracodeNode, FilterMitigation, NodeType, TreeGroupingHierarchy, FilterByPolicyImpact } from "./models/dataTypes";
import { VeracodeServiceAndData } from './veracodeServiceAndData';

import {getAppList,getAppChildren} from './apiWrappers/applicationsAPIWrapper';

const flawDiagnosticsPrefix: string = '#';

export class VeracodeExtensionModel {

	m_flawSorting: TreeGroupingHierarchy;
	m_mitigationFilter: FilterMitigation;
	m_impactPolicyFilter: FilterByPolicyImpact;
	credsHandler: CredsHandler;
	projectConfig: ProjectConfigHandler;
	veracodeService: VeracodeServiceAndData;
	private extensionDiagCollection: vscode.DiagnosticCollection;

	constructor(private m_configSettings: ConfigSettings) {
		this.credsHandler = new CredsHandler(this.m_configSettings.getCredsFile(),this.m_configSettings.getCredsProfile());
		this.projectConfig = new ProjectConfigHandler();
		this.m_flawSorting = TreeGroupingHierarchy.Severity;
		this.m_mitigationFilter = FilterMitigation.IncludeMitigated;
		this.m_impactPolicyFilter = FilterByPolicyImpact.AllFlaws;
		this.veracodeService = new VeracodeServiceAndData();
		this.extensionDiagCollection = vscode.languages.createDiagnosticCollection('Veracode');
	}


    // roots are going to be the Apps
	public get roots(): Thenable<VeracodeNode[]> {
		console.log('roots');
		let proxyHandler = new ProxyHandler(this.m_configSettings);
		proxyHandler.loadProxySettings();
		return getAppList(this.credsHandler,proxyHandler.proxySettings,this.projectConfig);
	}

	// will be the scans, sandboxes, flaw categories, and flaws
	public async getChildren(node: VeracodeNode): Promise<VeracodeNode[]> {
		log.debug('getting children of: '+node);

		let proxyHandler = new ProxyHandler(this.m_configSettings);
		proxyHandler.loadProxySettings();
		// get either app children --> sandboxes and scans
		switch (node.type) {
			case (NodeType.Application):  
				let sandboxCount = this.m_configSettings.getSandboxCount();
				// if App or Sandbox, get scans
				return getAppChildren(node, this.credsHandler,proxyHandler.proxySettings,this.projectConfig,sandboxCount);
			// Handle the result of a specific context		
			case (NodeType.Sandbox):
			case (NodeType.Policy):
				const sandboxNodes = await this.veracodeService.getSandboxNextLevel(node,this.credsHandler,proxyHandler.proxySettings,this.m_configSettings);
				this.addDiagnosticsForSandbox(node.id);
				return sandboxNodes;
			case (NodeType.Severity):
				return this.veracodeService.getFlawsOfSeverityNode(node);
			case (NodeType.CWE): 
				return this.veracodeService.getFlawsOfCWENode(node);
			case (NodeType.FlawCategory):
				return this.veracodeService.getFlawsOfFlawCategoryNode(node);
			default: 
				return [];
		}
	}
 
	public setFlawSorting(sort:TreeGroupingHierarchy) {
		this.m_flawSorting = sort;
		this.veracodeService.sortFindings(sort);
	}

	public setMitigationFilter(filter: FilterMitigation) {
		this.m_mitigationFilter = filter;
		this.veracodeService.updateFilterMitigations(filter);
	}

	public setImpactPolicyFilter(filter: FilterByPolicyImpact) {
		this.m_impactPolicyFilter = filter;
		this.veracodeService.updateFilterImpactPolicy(filter);
	}

	public getGrouping(): TreeGroupingHierarchy {
		return this.m_flawSorting;
	}

	public getMitigationFilter(): FilterMitigation{
		return this.m_mitigationFilter;
	}

	public getImpactPolicyFilter():FilterByPolicyImpact{
		return this.m_impactPolicyFilter;
	}

	public clearFlawsInfo (): void {
		this.extensionDiagCollection.clear();
		this.veracodeService.clearCache();
	}

	private addDiagnosticsForSandbox(sandboxNodeId:string) {
		const findings = this.veracodeService.getRawCacheData(sandboxNodeId);
		console.log(findings);
		console.log('got Raw scan data for scan');
		findings.forEach((rawFlaw: any) => {
			const findingDetails = getNested(rawFlaw,'finding_details');
			const findingStatus = getNested(rawFlaw,'finding_status');
			console.log(findingDetails);
			console.log(findingStatus);
			this.addDiagnosticItem(rawFlaw.issue_id+'',findingDetails,rawFlaw.description,findingStatus);

		});
	}

	private addDiagnosticItem(flawId:string,findingDetails:any,flawDesc:string,findingStatus:any){
		console.log('filename: '+findingDetails.file_name)
		const vscodeFileName = findVSCodeFilePath(findingDetails.file_name);
		console.log(`back from file finding ${vscodeFileName}`);
		if (vscodeFileName) {

			const flawSeverity = findingDetails.severity;
			const flawCategory = findingDetails.finding_category.name;
			const flawLineNumber = findingDetails.file_line_number;

			const mitigationStatus = findingStatus.resolution;
			const mitigationReviewStatus = findingStatus.resolution_status;

			var diagArray: Array<vscode.Diagnostic> = [];
			var range = new vscode.Range(flawLineNumber-1, 0, flawLineNumber-1, 0);

			let mitigationPrefix :string= '';
			if (mitigationStatus!=='none') {
				mitigationPrefix = `[${mitigationReviewStatus}] `;
			}
			var diag = new vscode.Diagnostic(
				range, 
				`${mitigationPrefix}${flawDiagnosticsPrefix}${flawId} - CWE-${findingDetails.cwe.id} ${findingDetails.cwe.name} (${flawCategory})`,
				this.mapSeverityToVSCodeSeverity(flawSeverity)
			);

			let uri = vscode.Uri.file(vscodeFileName);
			
			const html2textOptions = {
				'preserveNewlines':true,
				selectors: [
					{ selector: 'span', format: 'paragraph' }
				]
			};

			// Fix some formating in the HTML messages
			const partiallyFormattedDesc = flawDesc.replace(/References: /gi,'References:\n').replace(/<\/a>\s+<a/gi,'<\/a>\n<a');
			
			diag.relatedInformation = [new vscode.DiagnosticRelatedInformation(
				new vscode.Location(uri, range), convert(partiallyFormattedDesc,html2textOptions))];

			diag.source = 'Veracode Platform';

			// can't add to diag arrays for a URI, need to (re-)set instead?!?
			//diagArray = Array.clone(this.m_diagCollection.get(uri));
			diagArray = Object.assign([], this.extensionDiagCollection.get(uri));
			if( diagArray===undefined )
			{
				diagArray = [];
				diagArray.push(diag);
			
				this.extensionDiagCollection.set(uri, diagArray);
			}
			else {
				let newDiagArr:Array<vscode.Diagnostic> = diagArray;
				log.debug(newDiagArr);
				const existing = newDiagArr.filter((existingDiagnostic: vscode.Diagnostic) => {
					return (existingDiagnostic.message.indexOf(flawDiagnosticsPrefix+flawId) > -1);
				})
				if (existing.length===0){
					log.debug('issue not showing. adding to set');
					newDiagArr.push(diag);
					this.extensionDiagCollection.set(uri, newDiagArr);
				} else {
					log.debug('issue already showing');
				}
			}
		
		}
    }

	// VScode only supports 4 levels of Diagnostics (and we'll use only 3), while Veracode has 6
	private mapSeverityToVSCodeSeverity(sev: number): vscode.DiagnosticSeverity {
		switch(sev) {
			case 5:													// Veracode Very-High
			case 4: return vscode.DiagnosticSeverity.Error;			// Veracode High
			case 3: return vscode.DiagnosticSeverity.Warning;			// Veracode Medium
			default: return vscode.DiagnosticSeverity.Information;
			// ignore VSCode's 'Hints'
		}
	}
}


export class VeracodeTreeDataProvider implements vscode.TreeDataProvider<VeracodeNode> {

	private _onDidChangeTreeData: vscode.EventEmitter<any> = new vscode.EventEmitter<any>();
	readonly onDidChangeTreeData: vscode.Event<any> = this._onDidChangeTreeData.event;

    constructor(private readonly veracodeModel: VeracodeExtensionModel) { }

    // a bit sloppy in that it always refreshes from the root...??
	public refresh(): any {
		console.log('Refreshing');
        this._onDidChangeTreeData.fire(undefined);
	}

	public getTreeItem(element: VeracodeNode): vscode.TreeItem {
		let nodeType : NodeType = element.type;
		let command: vscode.Command | undefined = undefined;
		let retItem: vscode.TreeItem = {
			label: element.name,
			collapsibleState: element.type === NodeType.Flaw ? void 0: vscode.TreeItemCollapsibleState.Collapsed,
		}
		if (nodeType===NodeType.Application || nodeType===NodeType.Sandbox) {
			command = {
				title: nodeType+ 'selected',
				command: 'veracodeUnifiedExplorer.diagnosticsRefresh'
			};
			retItem.command = command;
		} else if (nodeType===NodeType.Flaw) {
			const rawFlaw = element.raw;
			const filePath = findVSCodeFilePath(getNested(rawFlaw,'finding_details','file_name'));
			const flawLineNumber = getNested(rawFlaw,'finding_details', 'file_line_number') || 1;
			if (filePath) {
				retItem.resourceUri = vscode.Uri.file(filePath);
				retItem.command = {
					command: 'vscode.open',
					title: 'Open Flaw Location',
					arguments: [
						retItem.resourceUri,
						<vscode.TextDocumentShowOptions>{
							selection: new vscode.Range(flawLineNumber-1, 0, flawLineNumber-1, 0),
							preserveFocus: true
						}
					]
				}
			}
			
			retItem.contextValue = 'flaw';
		}

		if (nodeType===NodeType.Policy || nodeType ===NodeType.Sandbox) {
			retItem.contextValue = 'sandbox';
		}
		
		return retItem;
	}

    /*
     * called with element == undefined for the root(s) - aka Apps
     * called again for each app to get the sandboxes and/or builds
	 * called again for each sandbox to get the builds
	 * called again for each build to get the categories
	 * called again to get the flaws in each category
     */
	public getChildren(element?: VeracodeNode): VeracodeNode[] | Thenable <VeracodeNode[]> {
		return element ? this.veracodeModel.getChildren(element) : this.veracodeModel.roots;
	}
}


 const findVSCodeFilePath = (fileName:string|undefined): string | undefined  => {
	if (!fileName) {
		log.warn('No file name provided for search');
		return;
	}

	// file matching constants
	let root: string|undefined = (vscode.workspace!== undefined && vscode.workspace.workspaceFolders !==undefined) ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined;
	let options: glob.IOptions = {cwd: root, nocase: true, ignore: ['target/**', '**/PrecompiledWeb/**','out/**','dist/**'], absolute: true,nodir:true};
	const matches = glob.sync('**/' + fileName, options);//, (err, matches) => {
	
	// take the first, log info if thre are multiple matches
	if(matches.length > 1) {
		log.info("Multiple matches found for source file " + fileName +
			": " + matches);
	}
	
	return matches[0];
}
