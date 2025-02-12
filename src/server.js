'use strict';

require('./services/Server');

const WireGuard = require('./services/WireGuard');

WireGuard.getConfig()
  .catch((err) => {
  // eslint-disable-next-line no-console
    console.error(err);

    // eslint-disable-next-line no-process-exit
    process.exit(1);
  });

// Handle terminate signal
process.on('SIGTERM', async () => {
  console.log('SIGTERM signal received.');
  await WireGuard.Shutdown();
  process.exit(0); // Exit gracefully
});

process.on('SIGINT', async () => { // Handle Ctrl+C as well
  console.log('SIGINT signal received.');
  await WireGuard.Shutdown();
  process.exit(0);
});
