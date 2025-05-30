const mockResponses = require('./responses');

// Add a global terminal store initialized from the mock response
const terminalStore = [ ...(mockResponses.terminalList.content.results || []) ];

const MockAPI = {
  createAddress: async (acct, payload) => {
    console.log('[MOCK] Creating address for account:', acct);
    return {
      ...mockResponses.address,
      content: {
        ...mockResponses.address.content,
        formattedAddress: payload.formattedAddress
      }
    };
  },

  getAvailableProducts: async (acct) => {
    console.log('[MOCK] Getting products for account:', acct);
    return mockResponses.products;
  },

  createServiceLine: async (acct, payload) => {
    console.log('[MOCK] Creating service line for account:', acct);
    return {
      ...mockResponses.serviceLine,
      content: {
        ...mockResponses.serviceLine.content,
        addressReferenceId: payload.addressReferenceId
      }
    };
  },

  updateServiceLineNickname: async (acct, serviceLineNumber, body) => {
    console.log('[MOCK] Updating service line nickname:', serviceLineNumber);
    return {
      ...mockResponses.serviceLine,
      content: {
        ...mockResponses.serviceLine.content,
        nickname: body.nickname
      }
    };
  },

  listUserTerminals: async (acct, params = '') => {
    console.log('[MOCK] Listing terminals for account:', acct);
    let results = [...terminalStore];
    if (params && params.includes("searchString=")) {
      const kitNumber = params.split("searchString=")[1];
      results = results.filter(t => t.kitSerialNumber === kitNumber);
    }
    return { ...mockResponses.terminalList, content: { results } };
  },

  addUserTerminal: async (acct, deviceId) => {
    console.log('[MOCK] Adding terminal:', deviceId);
    // Create a new terminal and add it to the global store
    const newTerminal = {
      userTerminalId: `mock-${deviceId}-${Date.now()}`,
      kitSerialNumber: deviceId,
      status: "active"
    };
    terminalStore.push(newTerminal);
    return {
      ...mockResponses.userTerminal,
      content: {
        ...mockResponses.userTerminal.content,
        kitSerialNumber: deviceId
      }
    };
  },

  attachTerminal: async (acct, terminalId, serviceLineNumber) => {
    console.log('[MOCK] Attaching terminal:', terminalId, 'to service line:', serviceLineNumber);
    return mockResponses.attachTerminal;
  }
};

module.exports = MockAPI;