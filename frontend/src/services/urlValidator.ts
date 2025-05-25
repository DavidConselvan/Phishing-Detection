export interface UrlCheckResult {
  url: string;
  isSafe: boolean;
  reasons: string[];
}

export class UrlValidator {
  static async checkUrl(url: string): Promise<UrlCheckResult> {
    const reasons: string[] = [];
    let isSafe = true;

    try {
      if (!this.isValidUrl(url)) {
        return {
          url,
          isSafe: false,
          reasons: ['Invalid URL format']
        };
      }

      const { hostname } = new URL(url);

      if (/\d/.test(hostname)) {
        reasons.push('Contains numbers in domain');
        isSafe = false;
      }

      const subdomains = hostname.split('.').length - 2;
      if (subdomains > 2) {
        reasons.push('Excessive number of subdomains');
        isSafe = false;
      }

      if (/[^a-zA-Z0-9.-]/.test(hostname)) {
        reasons.push('Contains special characters in domain');
        isSafe = false;
      }

      return {
        url,
        isSafe,
        reasons: reasons.length > 0 ? reasons : ['URL appears safe']
      };
    } catch (error) {
      console.error('Error checking URL:', error);
      return {
        url,
        isSafe: false,
        reasons: ['Error checking URL']
      };
    }
  }

  static isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }
} 