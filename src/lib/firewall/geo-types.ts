/** Offline country attribution; coordinates describe map labels, not servers. */
export interface GeoLocation {
  ip: string;
  status: "located" | "non-public" | "unknown";
  countryCode?: string;
}

export interface GeoSnapshot {
  database: {
    provider: "DB-IP Lite";
    release: string;
    precision: "country";
    attributionUrl: "https://db-ip.com";
  };
  results: GeoLocation[];
}

export interface GeoCountry {
  code: string;
  name: string;
  nameDe: string;
  longitude: number;
  latitude: number;
}
