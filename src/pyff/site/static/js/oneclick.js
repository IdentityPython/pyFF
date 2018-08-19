window.OneClickDiscoveryComponent = zoid.create({

    // The html tag used to render my component
    tag: 'my-onclick-component',

    url: {
    	current: '/oneclick'
    },
    defaultEnv: 'current',

    // default dimensions for the component
    dimensions: {
    	width: '300px',
    	height: '80px'
    },
    
    // defines the log level in the JavaScript console
    defaultLogLevel: 'warn', // debug,info,warn,error
    
    // defines if the container should be resized
    autoResize: {
        width: true,
        height: true
    },
    
    // defined for an iframe context - see https://github.com/krakenjs/zoid/blob/master/docs/api.md for additional details
    contexts: {
        iframe: true,
        popup: false
    }
    
});