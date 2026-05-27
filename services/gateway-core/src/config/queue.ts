import amqplib from 'amqplib';

const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://localhost:5672';
const EXCHANGE_NAME = 'aegis_security_bus';
const QUEUE_NAME = 'blocked_threats_queue';
const ROUTING_KEY = 'threat.blocked';

let connection: amqplib.ChannelModel | null = null;
let channel: amqplib.Channel | null = null;

/**
 * Initializes the RabbitMQ connection, asserts the exchange/queues, and binds them.
 */
export const initQueue = async (): Promise<void> => {
    try {
        const conn = await amqplib.connect(RABBITMQ_URL);
        connection = conn;
        
        const chan = await conn.createChannel();
        channel = chan;

        // Assert a TOPIC exchange named 'aegis_security_bus'
        await chan.assertExchange(EXCHANGE_NAME, 'topic', {
            durable: true
        });

        // Assert a durable queue named 'blocked_threats_queue'
        await chan.assertQueue(QUEUE_NAME, {
            durable: true
        });

        // Bind the queue to the exchange using the routing key 'threat.blocked'
        await chan.bindQueue(QUEUE_NAME, EXCHANGE_NAME, ROUTING_KEY);

        console.log('🐇 [Aegis Message Bus] RabbitMQ Connection & Queue topology successfully initialized.');
    } catch (error: any) {
        console.error('🐇 [Aegis Message Bus Connection Failure] Failed open safely:', error.message);
    }
};

/**
 * Publishes a security threat payload to the 'aegis_security_bus' exchange.
 * Designed with a Fail-Open policy: catches all connection/broker issues and continues cleanly.
 */
export const publishThreatLog = async (payload: object): Promise<void> => {
    try {
        const chan = channel;
        if (!chan) {
            console.warn('[Queue Publisher Failure - Continuing Gateway Lifecycle] Channel not initialized.');
            return;
        }

        const messageBuffer = Buffer.from(JSON.stringify(payload));
        const published = chan.publish(EXCHANGE_NAME, ROUTING_KEY, messageBuffer, {
            persistent: true
        });

        if (!published) {
            console.warn('[Queue Publisher Warning - Buffer full or message not accepted]');
        }
    } catch (error: any) {
        console.warn('[Queue Publisher Failure - Continuing Gateway Lifecycle]', error.message);
    }
};
