'use strict';

const debug = require('debug')('WireGuard');
const crypto = require('node:crypto');
const QRCode = require('qrcode');
const CRC32 = require('crc-32');

const Util = require('./Util');
const ServerError = require('./ServerError');

// MongoDB connection
const mongoose = require('mongoose');

const {
  WG_HOST,
  WG_PORT,
  WG_CONFIG_PORT,
  WG_MTU,
  WG_DEFAULT_DNS,
  WG_DEFAULT_ADDRESS,
  WG_PERSISTENT_KEEPALIVE,
  WG_ALLOWED_IPS,
  WG_PRE_UP,
  WG_POST_UP,
  WG_PRE_DOWN,
  WG_POST_DOWN,
  WG_ENABLE_EXPIRES_TIME,
  WG_ENABLE_ONE_TIME_LINKS,
  MONGO_URI,
} = require('../config');


// MongoDB Schema
const wireguardSchema = new mongoose.Schema({
  server: {
    privateKey: { type: String, required: true },
    publicKey: { type: String, required: true },
    address: { type: String, required: true },
  },
  clients: { type: Map, of: Object, default: {} },
}, { collection: 'wireguard' });

const WireguardConfig = mongoose.model('WireguardConfig', wireguardSchema);

module.exports = class WireGuard {

  constructor() {
    this.dbConnected = false;
  }

  async __buildConfig() {
      this.__configPromise = Promise.resolve().then(async () => {
        if (!WG_HOST) {
          throw new Error('WG_HOST Environment Variable Not Set!');
        }

        debug('Loading configuration...');
        let config;

        //  Подключение к MongoDB с повторными попытками.
        let retryCount = 0;
        const maxRetries = 5;
        const retryDelay = 5000; // 5 seconds

        while (retryCount <= maxRetries) {
            try {
              await mongoose.connect(MONGO_URI);
              console.log('Connected to MongoDB');
              this.dbConnected = true;
              break; // Successful connection, exit loop
            } catch (error) {
              console.error('MongoDB connection error:', error);
              this.dbConnected = false;
              retryCount++;

              if (retryCount <= maxRetries) {
                  console.log(`Retrying MongoDB connection in ${retryDelay/1000} seconds (attempt ${retryCount})...`);
                  await new Promise(resolve => setTimeout(resolve, retryDelay));
              } else {
                  console.error('Failed to connect to MongoDB after multiple retries.');
                  throw new Error('Failed to connect to MongoDB after multiple retries.');  // Throw after all retries
              }
            }
        }

        // Загружаем конфиг ПОСЛЕ успешного подключения.
        try {
            config = await WireguardConfig.findOne({});
            if (config) {
              debug('Configuration loaded from MongoDB.');
              config = config.toObject();
              config.clients = Object.fromEntries(config.clients);
            }
          } catch (dbError) {
            console.error('Error loading configuration from MongoDB:', dbError);
            throw dbError;
          }

          if (!config) {
            console.warn('No configuration found in MongoDB. Generating new configuration.');
            if (!this.dbConnected) {
              throw new Error('Cannot save initial configuration: Not connected to MongoDB.');
            }
            try{
                const privateKey = await Util.exec('wg genkey');
                const publicKey = await Util.exec(`echo ${privateKey} | wg pubkey`, {
                  log: 'echo ***hidden*** | wg pubkey',
                });
                const address = WG_DEFAULT_ADDRESS.replace('x', '1');

                config = {
                  server: {
                    privateKey,
                    publicKey,
                    address,
                  },
                  clients: {},
                };
                const newConfig = new WireguardConfig(config);
                await newConfig.save();
                debug('New configuration generated and saved to MongoDB.');
            } catch (error) {
                console.error("Error creating or saving initial config", error);
                throw error; // Re-throw for consistent error handling
            }
          }

        return config;
      });

      return this.__configPromise;
    }

  async getConfig() {
    if (!this.__configPromise) {
        await this.__buildConfig();
        await this.saveConfig(); // Initial save after building
    }
    return this.__configPromise;
}


  async saveConfig() {
    const config = await this.getConfig();
    await this.__saveConfig(config);
    try {
        await applyWireGuardConfig(config); // Применяем новую конфигурацию

    } catch (error) {
        console.error('Error applying WireGuard configuration:', error); // Более точное сообщение
        throw new ServerError('Failed to apply WireGuard configuration after save.', 500);  // Более точное сообщение
    }
}

  async __saveConfig(config) {
    debug('Config saving...');

    // Save to MongoDB
    if (this.dbConnected) {
      try {
        await WireguardConfig.updateOne({}, {
          $set: {
            server: config.server,
            clients: new Map(Object.entries(config.clients)),  // Save the clients as a Map
          },
        }, { upsert: true });
        debug('Configuration saved to MongoDB.');
      } catch (error) {
        console.error('Error saving to MongoDB:', error);
        throw new ServerError('Failed to save configuration to MongoDB', 500); // More specific error
      }
    }
    debug('Config saved.');
  }


  async getClients() {
    const config = await this.__buildConfig();
    const clients = Object.entries(config.clients).map(([clientId, client]) => ({
      id: clientId,
      name: client.name,
      enabled: client.enabled,
      address: client.address,
      publicKey: client.publicKey,
      createdAt: new Date(client.createdAt),
      updatedAt: new Date(client.updatedAt),
      expiredAt: client.expiredAt !== null
        ? new Date(client.expiredAt)
        : null,
      allowedIPs: client.allowedIPs,
      oneTimeLink: client.oneTimeLink ?? null,
      oneTimeLinkExpiresAt: client.oneTimeLinkExpiresAt ?? null,
      downloadableConfig: 'privateKey' in client,
      persistentKeepalive: null,
      latestHandshakeAt: null,
      transferRx: null,
      transferTx: null,
      endpoint: null,
    }));

    // Loop WireGuard status
    let dump = '';
    try {
        dump = await Util.exec('wg show wg0 dump', {
          log: false,
        });
    } catch (error) {
        console.warn('Error getting WireGuard dump (likely interface is down):', error.message); // Use console.warn, not error
        // Return the client list *without* handshake/transfer data.
        return clients.map(client => ({
            ...client,
            latestHandshakeAt: null,
            transferRx: null,
            transferTx: null,
            endpoint: null,
            persistentKeepalive: null,
        }));
    }

    dump
      .trim()
      .split('\n')
      .slice(1)
      .forEach((line) => {
        const [
          publicKey,
          preSharedKey, // eslint-disable-line no-unused-vars
          endpoint, // eslint-disable-line no-unused-vars
          allowedIps, // eslint-disable-line no-unused-vars
          latestHandshakeAt,
          transferRx,
          transferTx,
          persistentKeepalive,
        ] = line.split('\t');

        const client = clients.find((client) => client.publicKey === publicKey);
        if (!client) return;

        client.latestHandshakeAt = latestHandshakeAt === '0'
          ? null
          : new Date(Number(`${latestHandshakeAt}000`));
        client.endpoint = endpoint === '(none)' ? null : endpoint;
        client.transferRx = Number(transferRx);
        client.transferTx = Number(transferTx);
        client.persistentKeepalive = persistentKeepalive;
      });

    return clients;
  }

  async getClient({ clientId }) {
    const config = await this.getConfig();
    const client = config.clients[clientId];
    if (!client) {
      throw new ServerError(`Client Not Found: ${clientId}`, 404);
    }

    return client;
  }

  async getClientConfiguration({ clientId }) {
    const config = await this.getConfig();
    const client = await this.getClient({ clientId });

    return `
[Interface]
PrivateKey = ${client.privateKey ? `${client.privateKey}` : 'REPLACE_ME'}
Address = ${client.address}/24
${WG_DEFAULT_DNS ? `DNS = ${WG_DEFAULT_DNS}\n` : ''}\
${WG_MTU ? `MTU = ${WG_MTU}\n` : ''}\

[Peer]
PublicKey = ${config.server.publicKey}
${client.preSharedKey ? `PresharedKey = ${client.preSharedKey}\n` : ''
}AllowedIPs = ${WG_ALLOWED_IPS}
PersistentKeepalive = ${WG_PERSISTENT_KEEPALIVE}
Endpoint = ${WG_HOST}:${WG_CONFIG_PORT}`;
  }

  async getClientQRCodeSVG({ clientId }) {
    const config = await this.getClientConfiguration({ clientId });
    return QRCode.toString(config, {
      type: 'svg',
      width: 512,
    });
  }

  async createClient({ name, expiredDate }) {
      if (!name) {
        throw new Error('Missing: Name');
      }

      const config = await this.getConfig();
      let privateKey, publicKey, preSharedKey;

      try {
          privateKey = await Util.exec('wg genkey');
          publicKey = await Util.exec(`echo ${privateKey} | wg pubkey`, {
              log: 'echo ***hidden*** | wg pubkey',
          });
          preSharedKey = await Util.exec('wg genpsk');
      } catch (execError) {
          console.error("Error executing wg command:", execError);
          throw new ServerError("Failed to execute WireGuard command.", 500);
      }

      // Calculate next IP
      let address;
      for (let i = 2; i < 255; i++) {
        const client = Object.values(config.clients).find((client) => {
          return client.address === WG_DEFAULT_ADDRESS.replace('x', i);
        });

        if (!client) {
          address = WG_DEFAULT_ADDRESS.replace('x', i);
          break;
        }
      }

      if (!address) {
        throw new Error('Maximum number of clients reached.');
      }
      // Create Client
      const id = crypto.randomUUID();
      const client = {
        id,
        name,
        address,
        privateKey,
        publicKey,
        preSharedKey,

        createdAt: new Date(),
        updatedAt: new Date(),
        expiredAt: null,
        enabled: true,
      };
      if (expiredDate) {
        client.expiredAt = new Date(expiredDate);
        client.expiredAt.setHours(23);
        client.expiredAt.setMinutes(59);
        client.expiredAt.setSeconds(59);
      }

      config.clients[id] = client;

      await this.saveConfig(); // Сохранили изменения + применили конфиг

      return client;
    }

  async deleteClient({ clientId }) {
      const config = await this.getConfig();

      if (config.clients[clientId]) {
        delete config.clients[clientId];
        await this.saveConfig(); // Сохранили изменения + применили конфиг
      }
    }

  async enableClient({ clientId }) {
      const client = await this.getClient({ clientId });

      client.enabled = true;
      client.updatedAt = new Date();

      await this.saveConfig(); // Сохранили изменения + применили конфиг
    }

  async generateOneTimeLink({ clientId }) {
    const client = await this.getClient({ clientId });
    const key = `${clientId}-${Math.floor(Math.random() * 1000)}`;
    client.oneTimeLink = Math.abs(CRC32.str(key)).toString(16);
    client.oneTimeLinkExpiresAt = new Date(Date.now() + 5 * 60 * 1000);
    client.updatedAt = new Date();
    await this.saveConfig(); // No restart needed, just update data
  }

  async eraseOneTimeLink({ clientId }) {
    const client = await this.getClient({ clientId });
    // client.oneTimeLink = null;
    client.oneTimeLinkExpiresAt = new Date(Date.now() + 10 * 1000);
    client.updatedAt = new Date();
    await this.saveConfig(); // No restart needed, just update data
  }

  async disableClient({ clientId }) {
      const client = await this.getClient({ clientId });

      client.enabled = false;
      client.updatedAt = new Date();

      await this.saveConfig(); // Сохранили изменения + применили конфиг
    }

  async updateClientName({ clientId, name }) {
    const client = await this.getClient({ clientId });

    client.name = name;
    client.updatedAt = new Date();

    await this.saveConfig(); // No restart for name change
  }

  async updateClientAddress({ clientId, address }) {
      const client = await this.getClient({ clientId });

      if (!Util.isValidIPv4(address)) {
        throw new ServerError(`Invalid Address: ${address}`, 400);
      }

      client.address = address;
      client.updatedAt = new Date();
      await this.saveConfig(); // Сохранили изменения + применили конфиг

    }

  async updateClientExpireDate({ clientId, expireDate }) {
    const client = await this.getClient({ clientId });

    if (expireDate) {
      client.expiredAt = new Date(expireDate);
      client.expiredAt.setHours(23);
      client.expiredAt.setMinutes(59);
      client.expiredAt.setSeconds(59);
    } else {
      client.expiredAt = null;
    }
    client.updatedAt = new Date();

    await this.saveConfig(); //No restart required
  }

  async __reloadConfig() {
      await this.__buildConfig();
      try {
        const config = await this.getConfig(); // Get the config *after* rebuilding.
        await applyWireGuardConfig(config); // Apply the new config

      } catch (error) {
        console.error('Error applying WireGuard configuration:', error);  // Более точное сообщение
        throw new ServerError('Failed to apply WireGuard configuration after reload.', 500); // Более точное сообщение
      }
  }

  async restoreConfiguration(config) {
    debug('Starting configuration restore process.');
    try{
        const _config = config; // Уже объект
        if (!_config || typeof _config !== 'object' || !_config.server || !_config.clients) {
            throw new ServerError('Invalid configuration file format', 400);
        }

        await this.__saveConfig(_config);
        await this.__reloadConfig();
    } catch (error){
        console.error('Error restoring configuration:', error);
        throw new ServerError(`Failed to restore WireGuard configuration: ${error.message}`, error.statusCode || 500);
    }
    debug('Configuration restore process completed.');
  }

  async backupConfiguration() {
    debug('Starting configuration backup.');
    const config = await this.getConfig();
    const backup = JSON.stringify(config, null, 2);
    debug('Configuration backup completed.');
    return backup;
  }

  // Shutdown wireguard
    async Shutdown() {
      await Util.exec('wg setconf wg0 /dev/null').catch(() => {});
      await Util.exec('ip link delete dev wg0').catch(err => {
        if (!err.message.includes('Cannot find device')) {
            throw err;
        }
    });
  }

  async cronJobEveryMinute() {
    const config = await this.getConfig();
    let needSaveConfig = false;
    // Expires Feature
    if (WG_ENABLE_EXPIRES_TIME === 'true') {
      for (const client of Object.values(config.clients)) {
        if (client.enabled !== true) continue;
        if (client.expiredAt !== null && new Date() > new Date(client.expiredAt)) {
          debug(`Client ${client.id} expired.`);
          needSaveConfig = true;
          client.enabled = false;
          client.updatedAt = new Date();
        }
      }
    }
    // One Time Link Feature
    if (WG_ENABLE_ONE_TIME_LINKS === 'true') {
      for (const client of Object.values(config.clients)) {
        if (client.oneTimeLink !== null && new Date() > new Date(client.oneTimeLinkExpiresAt)) {
          debug(`Client ${client.id} One Time Link expired.`);
          needSaveConfig = true;
          client.oneTimeLink = null;
          client.oneTimeLinkExpiresAt = null;
          client.updatedAt = new Date();
        }
      }
    }
    if (needSaveConfig) {
      await this.saveConfig();
    }
  }

  async getMetrics() {
    const clients = await this.getClients();
    let wireguardPeerCount = 0;
    let wireguardEnabledPeersCount = 0;
    let wireguardConnectedPeersCount = 0;
    let wireguardSentBytes = '';
    let wireguardReceivedBytes = '';
    let wireguardLatestHandshakeSeconds = '';
    for (const client of Object.values(clients)) {
      wireguardPeerCount++;
      if (client.enabled === true) {
        wireguardEnabledPeersCount++;
      }
      if (client.endpoint !== null) {
        wireguardConnectedPeersCount++;
      }
      wireguardSentBytes += `wireguard_sent_bytes{interface="wg0",enabled="${client.enabled}",address="${client.address}",name="${client.name}"} ${Number(client.transferTx)}\n`;
      wireguardReceivedBytes += `wireguard_received_bytes{interface="wg0",enabled="${client.enabled}",address="${client.address}",name="${client.name}"} ${Number(client.transferRx)}\n`;
      wireguardLatestHandshakeSeconds += `wireguard_latest_handshake_seconds{interface="wg0",enabled="${client.enabled}",address="${client.address}",name="${client.name}"} ${client.latestHandshakeAt ? (new Date().getTime() - new Date(client.latestHandshakeAt).getTime()) / 1000 : 0}\n`;
    }

    let returnText = '# HELP wg-easy and wireguard metrics\n';

    returnText += '\n# HELP wireguard_configured_peers\n';
    returnText += '# TYPE wireguard_configured_peers gauge\n';
    returnText += `wireguard_configured_peers{interface="wg0"} ${Number(wireguardPeerCount)}\n`;

    returnText += '\n# HELP wireguard_enabled_peers\n';
    returnText += '# TYPE wireguard_enabled_peers gauge\n';
    returnText += `wireguard_enabled_peers{interface="wg0"} ${Number(wireguardEnabledPeersCount)}\n`;

    returnText += '\n# HELP wireguard_connected_peers\n';
    returnText += '# TYPE wireguard_connected_peers gauge\n';
    returnText += `wireguard_connected_peers{interface="wg0"} ${Number(wireguardConnectedPeersCount)}\n`;

    returnText += '\n# HELP wireguard_sent_bytes Bytes sent to the peer\n';
    returnText += '# TYPE wireguard_sent_bytes counter\n';
    returnText += `${wireguardSentBytes}`;

    returnText += '\n# HELP wireguard_received_bytes Bytes received from the peer\n';
    returnText += '# TYPE wireguard_received_bytes counter\n';
    returnText += `${wireguardReceivedBytes}`;

    returnText += '\n# HELP wireguard_latest_handshake_seconds UNIX timestamp seconds of the last handshake\n';
    returnText += '# TYPE wireguard_latest_handshake_seconds gauge\n';
    returnText += `${wireguardLatestHandshakeSeconds}`;

    return returnText;
  }

  async getMetricsJSON() {
    const clients = await this.getClients();
    let wireguardPeerCount = 0;
    let wireguardEnabledPeersCount = 0;
    let wireguardConnectedPeersCount = 0;
    for (const client of Object.values(clients)) {
      wireguardPeerCount++;
      if (client.enabled === true) {
        wireguardEnabledPeersCount++;
      }
      if (client.endpoint !== null) {
        wireguardConnectedPeersCount++;
      }
    }
    return {
      wireguard_configured_peers: Number(wireguardPeerCount),
      wireguard_enabled_peers: Number(wireguardEnabledPeersCount),
      wireguard_connected_peers: Number(wireguardConnectedPeersCount),
    };
  }

};

async function applyWireGuardConfig(config) {
  try {
    // 1. Удаляем интерфейс, если он существует.
    await Util.exec('wg setconf wg0 /dev/null').catch(() => {});
        await Util.exec('ip link delete dev wg0').catch(err => {
        // Игнорируем ошибку, если интерфейс не существует.
        if (!err.message.includes('Cannot find device')) {
          throw err;
        }
      });
    // 2. Создаем интерфейс.
      await Util.exec('ip link add dev wg0 type wireguard').catch(err => {
        // Игнорируем ошибку, если интерфейс уже существует.
        if (!err.message.includes('File exists')) { // эта ошибка не должна возникать
          throw err;
        }
      });

    // 3. Устанавливаем приватный ключ сервера.
    await Util.exec(`wg set wg0 private-key <(echo "${config.server.privateKey}")`);

    // 4. Устанавливаем порт прослушивания.
    await Util.exec(`wg set wg0 listen-port ${WG_PORT}`);

    // 5. Настраиваем IP-адрес сервера.
    await Util.exec(`ip address add ${config.server.address}/24 dev wg0`);

    // 6. Поднимаем интерфейс.
    await Util.exec('ip link set up dev wg0');


    // 7. Добавляем пиров (клиентов).
    for (const [clientId, client] of Object.entries(config.clients)) {
      if (!client.enabled) continue;

      let peerConfig = `wg set wg0 peer ${client.publicKey} allowed-ips ${client.address}/32`;

      if (client.preSharedKey) {
        peerConfig += ` preshared-key <(echo "${client.preSharedKey}")`;
      }
          await Util.exec(peerConfig);
    }

      if (WG_MTU) await Util.exec(`ip link set mtu ${WG_MTU} dev wg0`);


  } catch (error) {
    console.error('Error applying WireGuard configuration:', error);
    throw new ServerError('Failed to apply WireGuard configuration', 500);
  }
}