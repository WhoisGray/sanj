export namespace engine {
	
	export class CustomStagedNode {
	    id: string;
	    hostname: string;
	    resolved_ip: string;
	    country: string;
	    country_code: string;
	    port: number;
	    architecture: string;
	    status: string;
	    latitude: number;
	    longitude: number;
	
	    static createFrom(source: any = {}) {
	        return new CustomStagedNode(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.hostname = source["hostname"];
	        this.resolved_ip = source["resolved_ip"];
	        this.country = source["country"];
	        this.country_code = source["country_code"];
	        this.port = source["port"];
	        this.architecture = source["architecture"];
	        this.status = source["status"];
	        this.latitude = source["latitude"];
	        this.longitude = source["longitude"];
	    }
	}
	export class ProviderInfo {
	    id: string;
	    name: string;
	    type: string;
	    protocols: string[];
	    description: string;
	
	    static createFrom(source: any = {}) {
	        return new ProviderInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.type = source["type"];
	        this.protocols = source["protocols"];
	        this.description = source["description"];
	    }
	}
	export class UnifiedServer {
	    id: string;
	    name: string;
	    hostname: string;
	    ip: string;
	    country: string;
	    country_code: string;
	    city: string;
	    region: string;
	    load: number;
	    status: string;
	    protocols: string[];
	    wg_public_key?: string;
	    latitude: number;
	    longitude: number;
	    provider: string;
	
	    static createFrom(source: any = {}) {
	        return new UnifiedServer(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.hostname = source["hostname"];
	        this.ip = source["ip"];
	        this.country = source["country"];
	        this.country_code = source["country_code"];
	        this.city = source["city"];
	        this.region = source["region"];
	        this.load = source["load"];
	        this.status = source["status"];
	        this.protocols = source["protocols"];
	        this.wg_public_key = source["wg_public_key"];
	        this.latitude = source["latitude"];
	        this.longitude = source["longitude"];
	        this.provider = source["provider"];
	    }
	}
	export class UnifiedResult {
	    id: string;
	    server: UnifiedServer;
	    verdict: string;
	    ping_ms: number;
	    ike: string;
	    ike_ms: number;
	    ike_phase1: string;
	    ike_phase2: string;
	    ike_port: number;
	    wg: string;
	    wg_ms: number;
	    ovpn: string;
	    ovpn_ms: number;
	    firewall?: string;
	    details?: string;
	    tested_at: string;
	
	    static createFrom(source: any = {}) {
	        return new UnifiedResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.server = this.convertValues(source["server"], UnifiedServer);
	        this.verdict = source["verdict"];
	        this.ping_ms = source["ping_ms"];
	        this.ike = source["ike"];
	        this.ike_ms = source["ike_ms"];
	        this.ike_phase1 = source["ike_phase1"];
	        this.ike_phase2 = source["ike_phase2"];
	        this.ike_port = source["ike_port"];
	        this.wg = source["wg"];
	        this.wg_ms = source["wg_ms"];
	        this.ovpn = source["ovpn"];
	        this.ovpn_ms = source["ovpn_ms"];
	        this.firewall = source["firewall"];
	        this.details = source["details"];
	        this.tested_at = source["tested_at"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace main {
	
	export class SelectedFileData {
	    path: string;
	    content: string;
	
	    static createFrom(source: any = {}) {
	        return new SelectedFileData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.content = source["content"];
	    }
	}

}

