import {APIHandler} from '../util/apiQueryHandler';
import { CredsHandler } from '../util/credsHandler';
import { VeracodeNode, NodeType } from '../models/dataTypes';
import { ProxySettings } from '../util/proxyHandler';
import { ProjectConfigHandler } from '../util/projectConfigHandler';
import {getNested} from '../util/jsonUtil';

import log from 'loglevel';
import axios from 'axios';


const API_BASE_PATH:string = '/appsec/v1/applications'
export const POLICY_CONTAINER_NAME = 'POLICY';


const applicationRequest = async (credentialHandler:CredsHandler, proxySettings: ProxySettings|null,appGUID:string|null,appName:string|null, API_HOST:string|'api.veracode.com') => {
    let applications = {};
    let params:any= {};
    let path = API_BASE_PATH;
    if (appGUID) {
        path = `${API_BASE_PATH}/${appGUID}`;
    }
    if (appName) {
        params.name = appName;
    }
    try {
        applications = await APIHandler.request(
            API_HOST,
            path,
            params,
            'get',
            undefined,
            credentialHandler,  
            proxySettings  
        );
        console.log("Finished applicationRequest API request");
        
    } catch (error) {
        if (axios.isAxiosError(error)) {
            log.error(error.response);
        }
        return {};
    }
    console.log('end getApplication request');
    return applications;
}

const sandboxRequest = async (credentialHandler:CredsHandler, proxySettings: ProxySettings|null,appGUID:string,sandboxGUID:string|null,sandboxName:string|null,API_HOST:string|'api.veracode.com') => {
    let sandboxes = {};
    let path = `${API_BASE_PATH}/${appGUID}/sandboxes`;

    if (sandboxGUID) {
        path = `${path}/${sandboxGUID}`;
    }
    try {
        sandboxes = await APIHandler.request(
            API_HOST,
            path,
            {},
            'get',
            undefined,
            credentialHandler,  
            proxySettings  
        );
        console.log("Finished API request");
        
    } catch (error) {
        if (axios.isAxiosError(error)) {
            log.error(error.response);
        }
        return {};
    }
    console.log('end getSandboxes request');
    return sandboxes;
}

export const getApplications = async (credentialHandler:CredsHandler, proxySettings: ProxySettings|null, API_HOST:string|'api.veracode.com') => {
    console.log('getApplications');
    let applications:any = await applicationRequest(credentialHandler,proxySettings,null,null,API_HOST);
    console.log('end getApplications');
    if (applications.data) {
        return applications.data._embedded.applications;
    } else {
        return applications;
    }
}

export const getApplicationByGUID = async (credentialHandler:CredsHandler, proxySettings: ProxySettings|null,appGUID:string) => {
    console.log('getApplicationByGUID');
    let application = await applicationRequest(credentialHandler,proxySettings,appGUID,null,'api.veracode.com');
    console.log('end getApplicationByGUID');
    return application;
}

export const getApplicationByName = async (credentialHandler:CredsHandler, proxySettings: ProxySettings|null,appName:string,API_HOST:string|'api.veracode.com') => {
    // legacy_id
    console.info(`getApplicationByName - START - ${escape(appName)}`);
    let application:any = await applicationRequest(credentialHandler,proxySettings,null,appName, API_HOST);
    console.info('getApplicationByName - END');
    if (getNested(application,'data','_embedded')) {
        return application.data._embedded.applications;
    } else {
        return [];
    }
}

    // get the app list via API call
export const getAppList = async (credentialHandler:CredsHandler, proxySettings: ProxySettings|null,projectConfig:ProjectConfigHandler): Promise<VeracodeNode[]> => {
    log.debug('getAppList');
    /* (re-)loading the creds and proxy info here should be sufficient to pick up 
        * any changes by the user, as once they get the App List working they should 
        * be good to go and not make more changes
        */

    // (re-)load the creds, in case the user changed them
    try {
        await credentialHandler.loadCredsFromFile();
        await projectConfig.loadProjectConfigFromFile();
    }
    catch (error) {
        if (error instanceof Error) {
            log.error(error.message);
        } 
        return Promise.resolve([]);
    }
    const API_HOST = projectConfig.getRegion()
    console.log('API_HOST: '+API_HOST)
    

    let applications: any;
    if (projectConfig.getApplicationName()) {
        applications = await getApplicationByName(credentialHandler,proxySettings,projectConfig.getApplicationName()!, API_HOST);
    } else {
        applications = await getApplications(credentialHandler,proxySettings, API_HOST);
    }
    
    return new Promise((resolve,reject) => {
        const appNodes = handleAppList(applications);
        if (appNodes.length>0) {
            resolve(appNodes);
        } else {
            log.error("Empty results or could not get the requested application/s from the Veracode Platform");
            reject();
        }
    })
}

    // parse the app list from raw XML into an array of BuildNodes
const handleAppList = (applications: any) /*(rawXML: string)*/: VeracodeNode[] => {
    log.debug(applications);

    let appArray : VeracodeNode[] = [];

    if (typeof applications==='object' && applications.length) {
        appArray = applications.map((app:any) => {
            return new VeracodeNode(NodeType.Application, app.profile.name, app.guid, '0');
        });
    }

    return appArray;
}

export const getSandboxList = async (credentialHandler:CredsHandler, proxySettings: ProxySettings|null,appGUID:string, API_HOST:string|'api.veracode.com'):Promise<Array<any>> => {
    console.log('getSandboxList');
    let sandboxes:any = await sandboxRequest(credentialHandler,proxySettings,appGUID,null,null,API_HOST);
    console.log('end getSandboxList');

    if (sandboxes.data){
        if (getNested(sandboxes,'data','_embedded','sandboxes')) {
            return sandboxes.data._embedded.sandboxes;
        }
    } else {
        log.error('Error getting results for sandboxes list');
        log.error(JSON.stringify(sandboxes));
    }
    log.info('No sandboxes found');
    return [];
}

export const getSandboxByName = async (credentialHandler:CredsHandler, proxySettings: ProxySettings|null,appGUID:string,sandboxName:string, API_HOST:string|'api.veracode.com') => {
    console.log('getSandboxByName');
    let sandboxes:Array<any> = await getSandboxList(credentialHandler,proxySettings,appGUID, API_HOST);
    console.log('end getSandboxByName');
    return sandboxes.filter((sandbox)=> {
        return sandbox.name===sandboxName;
    });
}

const handleSandboxList = (sandboxes: any) : VeracodeNode[] => {
    log.debug("handling sandbox List: " + JSON.stringify(sandboxes));

    let sandboxArray : VeracodeNode[] = [];

    if (typeof sandboxes==='object' && sandboxes.length) {
        sandboxArray = sandboxes.map((sandbox:any) => {
            const name = sandbox.name === POLICY_CONTAINER_NAME ? POLICY_CONTAINER_NAME : `Sandbox - ${sandbox.name}`;
            const nodeType = sandbox.name === POLICY_CONTAINER_NAME ? NodeType.Policy : NodeType.Sandbox;
            const sandboxGUID = sandbox.name === POLICY_CONTAINER_NAME ?  undefined : sandbox.guid;
            return new VeracodeNode(nodeType, name, sandbox.guid, sandbox.application_guid,sandboxGUID,sandbox.application_guid);
        });
    }

    return sandboxArray;
    
}

 // get the children of the App (aka sandboxes and scans)
export const getAppChildren = async (appNode: VeracodeNode,
                                    credentialHandler:CredsHandler, 
                                    proxySettings: ProxySettings|null,
                                    projectConfig:ProjectConfigHandler, 
                                    sandboxCount: number): Promise<VeracodeNode[]> => {
    log.debug('getAppChildren');
    await projectConfig.loadProjectConfigFromFile();

    let sandboxes: any = [
        {
            guid: `${appNode.id}-policy`,
            name: POLICY_CONTAINER_NAME,
            application_guid: appNode.id
        }
    ];
    const API_HOST = projectConfig.getRegion()

    if (projectConfig.isPolicySandbox()) {
        // do nothing here
    } else if (projectConfig.getSandboxName()) {
        sandboxes = await getSandboxByName(credentialHandler,proxySettings,appNode.id,projectConfig.getApplicationName()!, API_HOST);
    } else {
        const sandboxesList = await getSandboxList(credentialHandler,proxySettings,appNode.id, API_HOST);
        sandboxes = sandboxes.concat(sandboxesList);
    }

    console.log(sandboxes);

    return new Promise((resolve,reject) => {
        const sandboxNodes = handleSandboxList(sandboxes);
        if (sandboxNodes.length>0) {
            resolve(sandboxNodes);
        } else {
            log.error("Could not get the requested sandbox/es from the Veracode Platform");
            reject();
        }
    })
}

