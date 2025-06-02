const mockResponses = {
  address: {
    content: {
      addressReferenceId: "mock-addr-123",
      formattedAddress: "1 Mock Street, Test City, TS 12345",
      latitude: 1.234567,
      longitude: -1.234567
    },
    errors: [],
    warnings: [],
    information: [],
    isValid: true
  },

  products: {
    content: {
      totalCount: 1,
      pageIndex: 0,
      limit: 50,
      isLastPage: true,
      results: [
        {
          productReferenceId: "mock-starlink-plan",
          name: "Mock Starlink Plan",
          price: 64.5,
          isoCurrencyCode: "USD",
          isSla: false,
          maxNumberOfUserTerminals: 1,
          dataProducts: null
        }
      ]
    },
    errors: [],
    warnings: [],
    information: [],
    isValid: true
  },

  serviceLine: {
    content: {
      addressReferenceId: "mock-addr-123",
      serviceLineNumber: "SL-5125283-42488-77",
      nickname: "Mock Service",
      productReferenceId: "mock-starlink-plan",
      startDate: new Date().toISOString(),
      endDate: null,
      publicIp: false,
      active: true
    },
    errors: [],
    warnings: [],
    information: [],
    isValid: true
  },

  userTerminal: {
    content: {
      userTerminalId: "UT-MOCK-123",
      kitSerialNumber: "KIT-MOCK-123",
      status: "active"
    },
    errors: [],
    warnings: [],
    information: [],
    isValid: true
  },

  terminalList: {
    content: {
      totalCount: 1,
      results: [
        {
          userTerminalId: "UT-MOCK-123",
          kitSerialNumber: "KIT-MOCK-12345",
          status: "active"
        }
      ]
    },
    errors: [],
    warnings: [],
    information: [],
    isValid: true
  },

  attachTerminal: {
    content: {
      status: "success"
    },
    errors: [],
    warnings: [],
    information: [],
    isValid: true
  }
};

module.exports = mockResponses;