// test/utils/dev-otp-store.ts
export class DevOtpStore {
    private static store: Record<string, string> = {};
  
    static set(phone: string, otp: string) {
      DevOtpStore.store[phone] = otp;
    }
  
    static get(phone: string): string | undefined {
      return DevOtpStore.store[phone];
    }
  
    static clear(phone: string) {
      delete DevOtpStore.store[phone];
    }
  }
  