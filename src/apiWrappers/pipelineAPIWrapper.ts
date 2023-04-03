import { URL, URLSearchParams } from 'url';
import globalAxios,{ AxiosInstance, AxiosPromise } from 'axios';
import * as FormData from "form-data";
import { CredsHandler } from '../util/credsHandler';
import { generateHeader } from '../util/veracode-hmac';
import { ProjectConfigHandler } from '../util/projectConfigHandler';

//const BASE_PATH: string = 'https://api.veracode.eu/pipeline_scan/v1'.replace(/\/+$/, "");

const BASE_PATH: string = '/pipeline_scan/v1'.replace(/\/+$/, "");


//console.log('pipelineAPIWrapper API_HOST: '+API_HOST)

export function addInterceptor(credsHandler:CredsHandler,):number {
    return globalAxios.interceptors.request.use(function (config) {
        if (config.url && config.method && credsHandler.getApiId()) {
            let url = new URL(config.url);
            config.headers!.Authorization = generateHeader(credsHandler.getApiId()!,credsHandler.getApiKey()!, url.host, url.pathname, url.search, config.method.toUpperCase());
        }
        config.headers!.Accept ='application/json';
        config.headers!['User-Agent']='Veracode-VSCode-Unified';
        return config;
      }, function (error) {
        return Promise.reject(error);
      });
}

export function removeGlobalInterceptor(interceptor:number){
    globalAxios.interceptors.request.eject(interceptor);
}


export interface ConfigurationParameters {
    apiKey?: string | Promise<string> | ((name: string) => string) | ((name: string) => Promise<string>);
    username?: string;
    password?: string;
    accessToken?: string | Promise<string> | ((name?: string, scopes?: string[]) => string) | ((name?: string, scopes?: string[]) => Promise<string>);
    basePath?: string;
    baseOptions?: any;
}

export class Configuration {
    /**
     * parameter for apiKey security
     * @param name security name
     * @memberof Configuration
     */
    apiKey?: string | Promise<string> | ((name: string) => string) | ((name: string) => Promise<string>);
    /**
     * parameter for basic security
     *
     * @type {string}
     * @memberof Configuration
     */
    username?: string;
    /**
     * parameter for basic security
     *
     * @type {string}
     * @memberof Configuration
     */
    password?: string;
    /**
     * parameter for oauth2 security
     * @param name security name
     * @param scopes oauth2 scope
     * @memberof Configuration
     */
    accessToken?: string | Promise<string> | ((name?: string, scopes?: string[]) => string) | ((name?: string, scopes?: string[]) => Promise<string>);
    /**
     * override base path
     *
     * @type {string}
     * @memberof Configuration
     */
    basePath?: string;
    /**
     * base options for axios calls
     *
     * @type {any}
     * @memberof Configuration
     */
    baseOptions?: any;

    constructor(param: ConfigurationParameters = {}) {
        this.apiKey = param.apiKey;
        this.username = param.username;
        this.password = param.password;
        this.accessToken = param.accessToken;
        this.basePath = param.basePath;
        this.baseOptions = param.baseOptions;
    }
}

/**
 * 
 * @export
 * @interface ErrorLinks
 */
 export interface ErrorLinks {
    /**
     * 
     * @type {Link}
     * @memberof ErrorLinks
     */
    help: Link;
}
/**
 * 
 * @export
 * @interface Files
 */
export interface Files {
    /**
     * 
     * @type {SourceFile}
     * @memberof Files
     */
    source_file: SourceFile;
}
/**
 * Each scan result has corresponding hash values to compare over time. When the hash numbers for cause_hash, cause_hash_ordinal, prototype_hash, procedure_hash, cause_hash_count, flaw_hash_ordinal, flaw_hash, and flaw_hash_count all match, then the flaw has not changed since a previous scan.
 * @export
 * @interface FlawMatch
 */
export interface FlawMatch {
    /**
     * 
     * @type {string}
     * @memberof FlawMatch
     */
    cause_hash?: string;
    /**
     * 
     * @type {number}
     * @memberof FlawMatch
     */
    cause_hash_count?: number;
    /**
     * 
     * @type {number}
     * @memberof FlawMatch
     */
    cause_hash_ordinal?: number;
    /**
     * 
     * @type {string}
     * @memberof FlawMatch
     */
    flaw_hash?: string;
    /**
     * 
     * @type {number}
     * @memberof FlawMatch
     */
    flaw_hash_count?: number;
    /**
     * 
     * @type {number}
     * @memberof FlawMatch
     */
    flaw_hash_ordinal?: number;
    /**
     * 
     * @type {string}
     * @memberof FlawMatch
     */
    procedure_hash?: string;
    /**
     * 
     * @type {string}
     * @memberof FlawMatch
     */
    prototype_hash?: string;
}
/**
 * 
 * @export
 * @interface Issue
 */
export interface Issue {
    /**
     * The Common Weakness Enumeration (CWE) ID for categorizing flaws.
     * @type {string}
     * @memberof Issue
     */
    cwe_id: string;
    /**
     * A detailed description of the flaw.
     * @type {string}
     * @memberof Issue
     */
    display_text: string;
    /**
     * 
     * @type {Files}
     * @memberof Issue
     */
    files: Files;
    /**
     * A link to a detailed description of the finding and associated CWE, as well as remediation guidance, if available.
     * @type {string}
     * @memberof Issue
     */
    flaw_details_link?: string;
    /**
     * 
     * @type {FlawMatch}
     * @memberof Issue
     */
    flaw_match: FlawMatch;
    /**
     * Single character, either G or B, indicating if the issue is a Good finding or a Bad finding. G is for Best Practices results and B if for discovered security flaws.
     * @type {string}
     * @memberof Issue
     */
    gob: string;
    /**
     * An integer starting at 1000 that uniquely identifies each flaw.
     * @type {number}
     * @memberof Issue
     */
    issue_id: number;
    /**
     * A short description of the flaw.
     * @type {string}
     * @memberof Issue
     */
    issue_type: string;
    /**
     * A label for the type of security flaw.
     * @type {string}
     * @memberof Issue
     */
    issue_type_id: string;
    /**
     * A number representing the Veracode flaw severity levels.
     * @type {number}
     * @memberof Issue
     */
    severity: number;
    /**
     * A label for the issue.
     * @type {string}
     * @memberof Issue
     */
    title: string;
    /**
     * A Veracode-specific ID number to differentiate between different types of flaw with the same CWE.
     * @type {string}
     * @memberof Issue
     */
    vc_id: string;
}
/**
 * 
 * @export
 * @interface Link
 */
export interface Link {
    /**
     * This is the endpoint related to the current request.
     * @type {string}
     * @memberof Link
     */
    href: string;
    /**
     * Name of the link.
     * @type {string}
     * @memberof Link
     */
    name?: string;
    /**
     * Property determining whether the href property is a template.
     * @type {boolean}
     * @memberof Link
     */
    templated?: boolean;
}
/**
 * 
 * @export
 * @interface ModelError
 */
export interface ModelError {
    /**
     * Error message.
     * @type {string}
     * @memberof ModelError
     */
    message?: string;
    /**
     * Error code.
     * @type {string}
     * @memberof ModelError
     */
    code?: string;
    /**
     * 
     * @type {ErrorLinks}
     * @memberof ModelError
     */
    _links?: ErrorLinks;
}
/**
 * 
 * @export
 * @interface RootResponse
 */
export interface RootResponse {
    /**
     * 
     * @type {RootResponseLinks}
     * @memberof RootResponse
     */
    _links?: RootResponseLinks;
}
/**
 * 
 * @export
 * @interface RootResponseLinks
 */
export interface RootResponseLinks {
    /**
     * 
     * @type {Link}
     * @memberof RootResponseLinks
     */
    root: Link;
    /**
     * 
     * @type {Link}
     * @memberof RootResponseLinks
     */
    self: Link;
    /**
     * 
     * @type {Link}
     * @memberof RootResponseLinks
     */
    help: Link;
    /**
     * 
     * @type {Link}
     * @memberof RootResponseLinks
     */
    create: Link;
}
/**
 * 
 * @export
 * @interface Scan
 */
export interface Scan {
    /**
     * The Veracode Platform application ID. It is free text provided by the user with the CI tool or API.
     * @type {string}
     * @memberof Scan
     */
    app_id?: string;
    /**
     * Project name.
     * @type {string}
     * @memberof Scan
     */
    project_name?: string;
    /**
     * Source control URI.
     * @type {string}
     * @memberof Scan
     */
    project_uri?: string;
    /**
     * The source control reference, revision, and/or branch.
     * @type {string}
     * @memberof Scan
     */
    project_ref?: string;
    /**
     * The commit hash for the files Veracode is scanning.
     * @type {string}
     * @memberof Scan
     */
    commit_hash?: string;
    /**
     * Development stage.
     * @type {string}
     * @memberof Scan
     */
    dev_stage?: ScanDevStageEnum;
    /**
     * Name of the scanned file.
     * @type {string}
     * @memberof Scan
     */
    binary_name: string;
    /**
     * Size of the scanned file.
     * @type {number}
     * @memberof Scan
     */
    binary_size: number;
    /**
     * SHA256 hash of the scanned file in hex format.
     * @type {string}
     * @memberof Scan
     */
    binary_hash: string;
    /**
     * User-defined timeout for scanning specified in minutes. Maximum allowed value is 60 minutes.
     * @type {number}
     * @memberof Scan
     */
    scan_timeout?: number;
}

/**
    * @export
    * @enum {string}
    */
export enum ScanDevStageEnum {
    DEVELOPMENT = 'DEVELOPMENT',
    TESTING = 'TESTING',
    RELEASE = 'RELEASE'
}

/**
 * 
 * @export
 * @interface ScanFindingsResource
 */
export interface ScanFindingsResource {
    /**
     * The scan identifier (UUID v4).
     * @type {string}
     * @memberof ScanFindingsResource
     */
    scan_id?: string;
    /**
     * Status of the scan.
     * @type {string}
     * @memberof ScanFindingsResource
     */
    scan_status?: ScanFindingsResourceScanStatusEnum;
    /**
     * 
     * @type {string}
     * @memberof ScanFindingsResource
     */
    message?: string;
    /**
     * 
     * @type {Array<Issue>}
     * @memberof ScanFindingsResource
     */
    findings?: Array<Issue>;
    /**
     * 
     * @type {ScanFindingsResourceLinks}
     * @memberof ScanFindingsResource
     */
    _links?: ScanFindingsResourceLinks;
}

/**
    * @export
    * @enum {string}
    */
export enum ScanFindingsResourceScanStatusEnum {
    PENDING = 'PENDING',
    UPLOADING = 'UPLOADING',
    STARTED = 'STARTED',
    SUCCESS = 'SUCCESS',
    FAILURE = 'FAILURE',
    CANCELLED = 'CANCELLED',
    TIMEOUT = 'TIMEOUT',
    USERTIMEOUT = 'USER_TIMEOUT'
}

/**
 * 
 * @export
 * @interface ScanFindingsResourceLinks
 */
export interface ScanFindingsResourceLinks {
    /**
     * 
     * @type {Link}
     * @memberof ScanFindingsResourceLinks
     */
    root: Link;
    /**
     * 
     * @type {Link}
     * @memberof ScanFindingsResourceLinks
     */
    self: Link;
    /**
     * 
     * @type {Link}
     * @memberof ScanFindingsResourceLinks
     */
    help: Link;
}
/**
 * 
 * @export
 * @interface ScanResource
 */
export interface ScanResource {
    /**
     * The scan identifier (UUID v4).
     * @type {string}
     * @memberof ScanResource
     */
    scan_id?: string;
    /**
     * Status of the scan.
     * @type {string}
     * @memberof ScanResource
     */
    scan_status?: ScanResourceScanStatusEnum;
    /**
     * Veracode Pipeline Scan API version.
     * @type {string}
     * @memberof ScanResource
     */
    api_version?: string;
    /**
     * The Veracode Platform application ID. It is free text provided by the user with the CI tool or API.
     * @type {string}
     * @memberof ScanResource
     */
    app_id?: string;
    /**
     * Project name.
     * @type {string}
     * @memberof ScanResource
     */
    project_name?: string;
    /**
     * Source control URI.
     * @type {string}
     * @memberof ScanResource
     */
    project_uri?: string;
    /**
     * The source control reference, revision, and/or branch.
     * @type {string}
     * @memberof ScanResource
     */
    project_ref?: string;
    /**
     * The commit hash for the files Veracode is scanning.
     * @type {string}
     * @memberof ScanResource
     */
    commit_hash?: string;
    /**
     * Development stage.
     * @type {string}
     * @memberof ScanResource
     */
    dev_stage?: ScanResourceDevStageEnum;
    /**
     * Name of the scanned file.
     * @type {string}
     * @memberof ScanResource
     */
    binary_name: string;
    /**
     * Size of the scanned file.
     * @type {number}
     * @memberof ScanResource
     */
    binary_size: number;
    /**
     * SHA256 hash of the scanned file in hex format.
     * @type {string}
     * @memberof ScanResource
     */
    binary_hash: string;
    /**
     * Number of segments into which the uploaded file must be divided.
     * @type {number}
     * @memberof ScanResource
     */
    binary_segments_expected?: number;
    /**
     * Number of uploaded segments.
     * @type {number}
     * @memberof ScanResource
     */
    binary_segments_uploaded?: number;
    /**
     * User-defined timeout for scanning specified in minutes. Maximum allowed value is 60 minutes.
     * @type {number}
     * @memberof ScanResource
     */
    scan_timeout?: number;
    /**
     * The scan duration in seconds.
     * @type {number}
     * @memberof ScanResource
     */
    scan_duration?: number;
    /**
     * Size of the scan results in bytes.
     * @type {number}
     * @memberof ScanResource
     */
    results_size?: number;
    /**
     * 
     * @type {string}
     * @memberof ScanResource
     */
    message?: string;
    /**
     * Date when the scan was created. The date/time format is per RFC3339 and ISO-8601, and the timezone is UTC. Example: 2019-04-12T23:20:50.52Z.
     * @type {string}
     * @memberof ScanResource
     */
    created?: string;
    /**
     * Date when the scan was recently updated. The date/time format is per RFC3339 and ISO-8601, and the timezone is UTC. Example: 2019-04-12T23:20:50.52Z.
     * @type {string}
     * @memberof ScanResource
     */
    changed?: string;
    /**
     * 
     * @type {ScanResourceLinks}
     * @memberof ScanResource
     */
    _links?: ScanResourceLinks;
}

/**
    * @export
    * @enum {string}
    */
export enum ScanResourceScanStatusEnum {
    PENDING = 'PENDING',
    UPLOADING = 'UPLOADING',
    STARTED = 'STARTED',
    SUCCESS = 'SUCCESS',
    FAILURE = 'FAILURE',
    CANCELLED = 'CANCELLED',
    TIMEOUT = 'TIMEOUT',
    USERTIMEOUT = 'USER_TIMEOUT'
}
/**
    * @export
    * @enum {string}
    */
export enum ScanResourceDevStageEnum {
    DEVELOPMENT = 'DEVELOPMENT',
    TESTING = 'TESTING',
    RELEASE = 'RELEASE'
}

/**
 * 
 * @export
 * @interface ScanResourceLinks
 */
export interface ScanResourceLinks {
    /**
     * 
     * @type {Link}
     * @memberof ScanResourceLinks
     */
    root: Link;
    /**
     * 
     * @type {Link}
     * @memberof ScanResourceLinks
     */
    self: Link;
    /**
     * 
     * @type {Link}
     * @memberof ScanResourceLinks
     */
    help: Link;
    /**
     * 
     * @type {Link}
     * @memberof ScanResourceLinks
     */
    create?: Link;
    /**
     * 
     * @type {Link}
     * @memberof ScanResourceLinks
     */
    details?: Link;
    /**
     * 
     * @type {Link}
     * @memberof ScanResourceLinks
     */
    upload?: Link;
    /**
     * 
     * @type {Link}
     * @memberof ScanResourceLinks
     */
    start?: Link;
    /**
     * 
     * @type {Link}
     * @memberof ScanResourceLinks
     */
    cancel?: Link;
    /**
     * 
     * @type {Link}
     * @memberof ScanResourceLinks
     */
    findings?: Link;
}
/**
 * 
 * @export
 * @interface ScanSegmentResource
 */
export interface ScanSegmentResource {
    /**
     * The scan identifier (UUID v4).
     * @type {string}
     * @memberof ScanSegmentResource
     */
    scan_id: string;
    /**
     * A zero-based index of the uploaded file segment.
     * @type {number}
     * @memberof ScanSegmentResource
     */
    segment_id: number;
    /**
     * Size of uploaded file segment.
     * @type {number}
     * @memberof ScanSegmentResource
     */
    segment_size: number;
    /**
     * SHA256 hash of the uploaded file segment in hex format.
     * @type {string}
     * @memberof ScanSegmentResource
     */
    segment_hash: string;
    /**
     * 
     * @type {ScanSegmentResourceLinks}
     * @memberof ScanSegmentResource
     */
    _links?: ScanSegmentResourceLinks;
}
/**
 * 
 * @export
 * @interface ScanSegmentResourceLinks
 */
export interface ScanSegmentResourceLinks {
    /**
     * 
     * @type {Link}
     * @memberof ScanSegmentResourceLinks
     */
    root: Link;
    /**
     * 
     * @type {Link}
     * @memberof ScanSegmentResourceLinks
     */
    self: Link;
    /**
     * 
     * @type {Link}
     * @memberof ScanSegmentResourceLinks
     */
    help: Link;
    /**
     * 
     * @type {Link}
     * @memberof ScanSegmentResourceLinks
     */
    upload?: Link;
    /**
     * 
     * @type {Link}
     * @memberof ScanSegmentResourceLinks
     */
    start?: Link;
    /**
     * 
     * @type {Link}
     * @memberof ScanSegmentResourceLinks
     */
    cancel: Link;
}
/**
 * 
 * @export
 * @interface ScanUpdate
 */
export interface ScanUpdate {
    /**
     * Status of the scan.
     * @type {string}
     * @memberof ScanUpdate
     */
    scan_status: ScanUpdateScanStatusEnum;
}

/**
    * @export
    * @enum {string}
    */
export enum ScanUpdateScanStatusEnum {
    STARTED = 'STARTED',
    CANCELLED = 'CANCELLED'
}

/**
 * 
 * @export
 * @interface SourceFile
 */
export interface SourceFile {
    /**
     * File path containing the flaw. UNKNOWN is returned, if not applicable.
     * @type {string}
     * @memberof SourceFile
     */
    file: string;
    /**
     * The name of the function with the flaw. UNKNOWN is returned, if not applicable.
     * @type {string}
     * @memberof SourceFile
     */
    function_name: string;
    /**
     * The function definition with parameters.
     * @type {string}
     * @memberof SourceFile
     */
    function_prototype: string;
    /**
     * The line number in the code where the flaw is found.
     * @type {number}
     * @memberof SourceFile
     */
    line: number;
    /**
     * The full name of the function with the flaw. UNKNOWN is returned, if not applicable.
     * @type {string}
     * @memberof SourceFile
     */
    qualified_function_name: string;
    /**
     * The parent class containing the flaw.
     * @type {string}
     * @memberof SourceFile
     */
    scope: string;
}

/**
 *
 * @export
 */
 export const COLLECTION_FORMATS = {
    csv: ",",
    ssv: " ",
    tsv: "\t",
    pipes: "|",
};

/**
 *
 * @export
 * @interface RequestArgs
 */
export interface RequestArgs {
    url: string;
    options: any;
}

/**
 *
 * @export
 * @class RequiredError
 * @extends {Error}
 */
export class RequiredError extends Error {
    name: "RequiredError" = "RequiredError";
    constructor(public field: string, msg?: string) {
        super(msg);
    }
}

/**
 * FindingsApi - axios parameter creator
 * @export
 */
export const FindingsApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * This endpoint returns the scan findings.
         * @param {string} scanId Scan identifier (UUID v4).
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        scansScanIdFindingsGet: async (scanId: string, options: any = {}): Promise<RequestArgs> => {
            let projectConfig = new ProjectConfigHandler
            await projectConfig.loadProjectConfigFromFile();
            const API_HOST = projectConfig.getRegion()
            return genericRequestParameterCreator('GET','/scans/{scan_id}/findings',scanId,API_HOST,options,configuration);
        },
    }
};

/**
 *
 * @export
 * @class BaseAPI
 */
 export class BaseAPI {
    protected configuration: Configuration | undefined;

    constructor(configuration?: Configuration, protected basePath: string = BASE_PATH, protected axios: AxiosInstance = globalAxios) {
        if (configuration) {
            this.configuration = configuration;
            this.basePath = configuration.basePath || this.basePath;
        }
    }
}

/**
 * FindingsApi - functional programming interface
 * @export
 */
export const FindingsApiFp = function(configuration?: Configuration) {
    return {
        /**
         * This endpoint returns the scan findings.
         * @param {string} scanId Scan identifier (UUID v4).
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */

        async scansScanIdFindingsGet(scanId: string, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ScanFindingsResource>> {
            const localVarAxiosArgs = await FindingsApiAxiosParamCreator(configuration).scansScanIdFindingsGet(scanId, options);
            let projectConfig = new ProjectConfigHandler
            await projectConfig.loadProjectConfigFromFile();
            const API_HOST = projectConfig.getRegion()
            const URLpath = 'https://'+API_HOST+BASE_PATH
            return (axios: AxiosInstance = globalAxios, basePath: string = URLpath) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: URLpath + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
    }
};

/**
 * FindingsApi - factory interface
 * @export
 */
export const FindingsApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    return {
        /**
         * This endpoint returns the scan findings.
         * @param {string} scanId Scan identifier (UUID v4).
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        scansScanIdFindingsGet(scanId: string, options?: any): AxiosPromise<ScanFindingsResource> {
            return FindingsApiFp(configuration).scansScanIdFindingsGet(scanId, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * FindingsApi - object-oriented interface
 * @export
 * @class FindingsApi
 * @extends {BaseAPI}
 */
export class FindingsApi extends BaseAPI {
    /**
     * This endpoint returns the scan findings.
     * @param {string} scanId Scan identifier (UUID v4).
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof FindingsApi
     */
    public scansScanIdFindingsGet(scanId: string, options?: any) {
        return FindingsApiFp(this.configuration).scansScanIdFindingsGet(scanId, options).then((request) => request(this.axios, this.basePath));
    }
}

/**
 * ScansApi - axios parameter creator
 * @export
 */
export const ScansApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * This endpoint is the first step in scanning a project with Veracode Pipeline Scan, where you submit details of the file to be scanned.
         * @param {Scan} scan Details of the file to be scanned.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        scansPost: async (scan: Scan, options: any = {}): Promise<RequestArgs> => {
            options.data = scan || "";
            let projectConfig = new ProjectConfigHandler
            await projectConfig.loadProjectConfigFromFile();
            const API_HOST = projectConfig.getRegion()
            return genericRequestParameterCreator('POST','/scans','',API_HOST,options,configuration);
        },
        /**
         * This endpoint returns scan details.
         * @param {string} scanId Scan identifier (UUID v4).
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        scansScanIdGet: async (scanId: string, options: any = {}): Promise<RequestArgs> => {
            let projectConfig = new ProjectConfigHandler
            await projectConfig.loadProjectConfigFromFile();
            const API_HOST = projectConfig.getRegion()
            return genericRequestParameterCreator('GET','/scans/{scan_id}',scanId,API_HOST,options,configuration);
        },
        /**
         * This endpoint allows to start / to cancel the scanning. User must submit an object having only the scan_status property with certain value.
         * @param {string} scanId Scan identifier (UUID v4).
         * @param {ScanUpdate} scan An object containing the property that determines the expected scan status.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        scansScanIdPut: async (scanId: string, scan: ScanUpdate, options: any = {}): Promise<RequestArgs> => {
            options.data = scan;
            let projectConfig = new ProjectConfigHandler
            await projectConfig.loadProjectConfigFromFile();
            const API_HOST = projectConfig.getRegion()
            return genericRequestParameterCreator('PUT','/scans/{scan_id}',scanId,API_HOST,options,configuration);
        },
    }
};

/**
 * ScansApi - functional programming interface
 * @export
 */
export const ScansApiFp = function(configuration?: Configuration) {
    return {
        /**
         * This endpoint is the first step in scanning a project with Veracode Pipeline Scan, where you submit details of the file to be scanned.
         * @param {Scan} scan Details of the file to be scanned.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async scansPost(scan: Scan, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ScanResource>> {
            const localVarAxiosArgs = await ScansApiAxiosParamCreator(configuration).scansPost(scan, options);
            let projectConfig = new ProjectConfigHandler
            await projectConfig.loadProjectConfigFromFile();
            const API_HOST = projectConfig.getRegion()
            const URLPath= 'https://'+API_HOST+BASE_PATH
            return (axios: AxiosInstance = globalAxios, basePath: string = URLPath) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: URLPath + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
        /**
         * This endpoint returns scan details.
         * @param {string} scanId Scan identifier (UUID v4).
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async scansScanIdGet(scanId: string, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ScanResource>> {
            const localVarAxiosArgs = await ScansApiAxiosParamCreator(configuration).scansScanIdGet(scanId, options);
            let projectConfig = new ProjectConfigHandler
            await projectConfig.loadProjectConfigFromFile();
            const API_HOST = projectConfig.getRegion()
            const URLpath = 'https://'+API_HOST+BASE_PATH
            return (axios: AxiosInstance = globalAxios, basePath: string = URLpath) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: URLpath + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
        /**
         * This endpoint allows to start / to cancel the scanning. User must submit an object having only the scan_status property with certain value.
         * @param {string} scanId Scan identifier (UUID v4).
         * @param {ScanUpdate} scan An object containing the property that determines the expected scan status.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async scansScanIdPut(scanId: string, scan: ScanUpdate, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ScanResource>> {
            const localVarAxiosArgs = await ScansApiAxiosParamCreator(configuration).scansScanIdPut(scanId, scan, options);
            let projectConfig = new ProjectConfigHandler
            await projectConfig.loadProjectConfigFromFile();
            const API_HOST = projectConfig.getRegion()
            const URLpath = 'https://'+API_HOST+BASE_PATH
            return (axios: AxiosInstance = globalAxios, basePath: string = URLpath) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: URLpath + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
    }
};

/**
 * ScansApi - object-oriented interface
 * @export
 * @class ScansApi
 * @extends {BaseAPI}
 */
export class ScansApi extends BaseAPI {
    /**
     * This endpoint is the first step in scanning a project with Veracode Pipeline Scan, where you submit details of the file to be scanned.
     * @param {Scan} scan Details of the file to be scanned.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ScansApi
     */
    public scansPost(scan: Scan, options?: any) {
        return ScansApiFp(this.configuration).scansPost(scan, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * This endpoint returns scan details.
     * @param {string} scanId Scan identifier (UUID v4).
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ScansApi
     */
    public scansScanIdGet(scanId: string, options?: any) {
        return ScansApiFp(this.configuration).scansScanIdGet(scanId, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * This endpoint allows to start / to cancel the scanning. User must submit an object having only the scan_status property with certain value.
     * @param {string} scanId Scan identifier (UUID v4).
     * @param {ScanUpdate} scan An object containing the property that determines the expected scan status.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ScansApi
     */
    public scansScanIdPut(scanId: string, scan: ScanUpdate, options?: any) {
        return ScansApiFp(this.configuration).scansScanIdPut(scanId, scan, options).then((request) => request(this.axios, this.basePath));
    }
}


/**
 * SegmentsApi - axios parameter creator
 * @export
 */
export const SegmentsApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Endpoint for uploading the scanned file segments. After you create a scan, it has the binary_segments_expected attribute. Divide your file into as many segments of roughly equal length and submit them using this endpoint.
         * @param {string} scanId Scan identifier (UUID v4).
         * @param {number} segmentId A zero-based index of the uploaded file segment.
         * @param {any} file The scanned file segment.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        scansScanIdSegmentsSegmentIdPut: async (scanId: string, segmentId: number, file: any, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'scanId' is not null or undefined
            if (scanId === null || scanId === undefined) {
                throw new RequiredError('scanId','Required parameter scanId was null or undefined when calling scansScanIdSegmentsSegmentIdPut.');
            }
            // verify required parameter 'segmentId' is not null or undefined
            if (segmentId === null || segmentId === undefined) {
                throw new RequiredError('segmentId','Required parameter segmentId was null or undefined when calling scansScanIdSegmentsSegmentIdPut.');
            }
            // verify required parameter 'file' is not null or undefined
            if (file === null || file === undefined) {
                throw new RequiredError('file','Required parameter file was null or undefined when calling scansScanIdSegmentsSegmentIdPut.');
            }
            const localVarPath = `/scans/{scan_id}/segments/{segment_id}`
                .replace(`{${"scan_id"}}`, encodeURIComponent(String(scanId)))
                .replace(`{${"segment_id"}}`, encodeURIComponent(String(segmentId)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let projectConfig = new ProjectConfigHandler
            await projectConfig.loadProjectConfigFromFile();
            const API_HOST = projectConfig.getRegion()
            let URLpath = 'https://'+API_HOST+BASE_PATH
            const localVarUrlObj = new URL(localVarPath,URLpath);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }
            const localVarRequestOptions = { method: 'PUT', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;
            const localVarFormParams = new FormData();

            localVarHeaderParameter['Content-Type'] = 'multipart/form-data';

            if (file !== undefined) { 
                localVarFormParams.append('file', file , 'file');
                localVarHeaderParameter['Content-Type'] = localVarFormParams.getHeaders()['content-type'];
            }
    
            const query = new URLSearchParams(localVarUrlObj.search);
            for (const key in localVarQueryParameter) {
                query.set(key, localVarQueryParameter[key]);
            }
            for (const key in options.query) {
                query.set(key, options.query[key]);
            }
            localVarUrlObj.search = (new URLSearchParams(query)).toString();
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            localVarRequestOptions.data = localVarFormParams;

            return {
                url: localVarUrlObj.pathname + localVarUrlObj.search + localVarUrlObj.hash,
                options: localVarRequestOptions,
            };
        },
    }
};

/**
 * SegmentsApi - functional programming interface
 * @export
 */
export const SegmentsApiFp = function(configuration?: Configuration) {
    return {
        /**
         * Endpoint for uploading the scanned file segments. After you create a scan, it has the binary_segments_expected attribute. Divide your file into as many segments of roughly equal length and submit them using this endpoint.
         * @param {string} scanId Scan identifier (UUID v4).
         * @param {number} segmentId A zero-based index of the uploaded file segment.
         * @param {any} file The scanned file segment.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async scansScanIdSegmentsSegmentIdPut(scanId: string, segmentId: number, file: any, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ScanSegmentResource>> {
            const localVarAxiosArgs = await SegmentsApiAxiosParamCreator(configuration).scansScanIdSegmentsSegmentIdPut(scanId, segmentId, file, options);
            let projectConfig = new ProjectConfigHandler
            await projectConfig.loadProjectConfigFromFile();
            const API_HOST = projectConfig.getRegion()
            let URLpath = 'https://'+API_HOST+BASE_PATH
            return (axios: AxiosInstance = globalAxios, basePath: string = URLpath) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: URLpath + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
    }
};

/**
 * SegmentsApi - factory interface
 * @export
 */
export const SegmentsApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    return {
        /**
         * Endpoint for uploading the scanned file segments. After you create a scan, it has the binary_segments_expected attribute. Divide your file into as many segments of roughly equal length and submit them using this endpoint.
         * @param {string} scanId Scan identifier (UUID v4).
         * @param {number} segmentId A zero-based index of the uploaded file segment.
         * @param {any} file The scanned file segment.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        scansScanIdSegmentsSegmentIdPut(scanId: string, segmentId: number, file: any, options?: any): AxiosPromise<ScanSegmentResource> {
            return SegmentsApiFp(configuration).scansScanIdSegmentsSegmentIdPut(scanId, segmentId, file, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * SegmentsApi - object-oriented interface
 * @export
 * @class SegmentsApi
 * @extends {BaseAPI}
 */
export class SegmentsApi extends BaseAPI {
    /**
     * Endpoint for uploading the scanned file segments. After you create a scan, it has the binary_segments_expected attribute. Divide your file into as many segments of roughly equal length and submit them using this endpoint.
     * @param {string} scanId Scan identifier (UUID v4).
     * @param {number} segmentId A zero-based index of the uploaded file segment.
     * @param {any} file The scanned file segment.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof SegmentsApi
     */
    public scansScanIdSegmentsSegmentIdPut(scanId: string, segmentId: number, file: any, options?: any) {
        return SegmentsApiFp(this.configuration).scansScanIdSegmentsSegmentIdPut(scanId, segmentId, file, options).then((request) => request(this.axios, this.basePath));
    }
}

function genericRequestParameterCreator(method:'GET'|'PUT'|'POST',path:string,scanId:string,API_HOST:any, options: any = {},configuration?: Configuration): {url:string,options:any} {
    // verify required parameter 'scanId' is not null or undefined
    if (scanId === null || scanId === undefined) {
        throw new RequiredError('scanId',`Required parameter scanId was null or undefined when calling ${method} ${path}.`);
    }
    const localVarPath = path
        .replace(`{${"scan_id"}}`, encodeURIComponent(String(scanId)));
    // use dummy base URL string because the URL constructor only accepts absolute URLs.
    let URLpath = 'https://'+API_HOST+BASE_PATH
    const localVarUrlObj = new URL(localVarPath,URLpath);
    let baseOptions;
    if (configuration) {
        baseOptions = configuration.baseOptions;
    }
    const localVarRequestOptions = { method, ...baseOptions, ...options};
    const localVarHeaderParameter = {} as any;

    localVarUrlObj.search = '';
    let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
    localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};

    return {
        url: localVarUrlObj.pathname,
        options: localVarRequestOptions,
    };
}


export async function updateScanStatus(scanId: string,scan_status: ScanUpdateScanStatusEnum) {
    return new ScansApi().scansScanIdPut(scanId, {   scan_status });
}

export async function getScanStatus(scanId:string) {
    return new ScansApi().scansScanIdGet(scanId);
}

export async function createNewScan(scanTargetDetails:Scan) {
    return new ScansApi().scansPost(scanTargetDetails);
}
