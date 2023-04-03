import {APIHandler} from '../util/apiQueryHandler';
import { CredsHandler } from '../util/credsHandler';
import { ProxySettings } from '../util/proxyHandler';
import { ProjectConfigHandler } from '../util/projectConfigHandler';

import log from 'loglevel';
import axios from 'axios';
import { glob } from 'glob';

const API_BASE_PATH:string = '/appsec/v1/applications'
export const POLICY_CONTAINER_NAME = 'POLICY';


export const summaryReportRequest = async (credentialHandler:CredsHandler, proxySettings: ProxySettings|null,appGUID:string|null,sandboxGUID:string|null) => {
    log.debug('SUMMARY Repost request - START');
    let report = {};
    let params:any= {};
    let path = `/appsec/v2/applications/${appGUID}/summary_report`;
    if (sandboxGUID) {
        params['context'] = sandboxGUID;
    }

    let projectConfig = new ProjectConfigHandler
    await projectConfig.loadProjectConfigFromFile();
    const API_HOST = projectConfig.getRegion()
    console.log('API_HOST_apiSpecificationsAPIWrapper: '+API_HOST)
    
    try {
        report = await APIHandler.request(
            API_HOST,
            path,
            params,
            'get',
            undefined,
            credentialHandler,  
            proxySettings  
        );
        log.debug("Finished API request");
        
    } catch (error) {
        if (axios.isAxiosError(error))  {
            log.error(error.response);
        }
        return {};
    }
    log.debug('SUMMARY Repost request - END');
    return report;
}



