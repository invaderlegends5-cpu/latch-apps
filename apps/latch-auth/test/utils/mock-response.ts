// simple Express-like response mock for Jest tests
export function createMockRes() {
    const res: any = {};
    res.status = jest.fn().mockImplementation((code: number) => {
      res.statusCode = code;
      return res;
    });
    res.json = jest.fn().mockImplementation((payload: any) => {
      res._json = payload;
      return res;
    });
    res.cookie = jest.fn().mockImplementation((name: string, value: any, opts?: any) => {
      // collect cookies for inspection if needed
      res._cookies = res._cookies || {};
      res._cookies[name] = { value, opts };
      return res;
    });
    res.clearCookie = jest.fn().mockImplementation((name: string, opts?: any) => {
      res._clearedCookies = res._clearedCookies || {};
      res._clearedCookies[name] = opts || true;
      return res;
    });
    res.send = jest.fn().mockImplementation((body?: any) => {
      res._sent = body;
      return res;
    });
    return res;
  }
  