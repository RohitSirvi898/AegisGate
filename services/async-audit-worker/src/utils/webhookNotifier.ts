import axios from 'axios';

export interface ThreatNotificationPayload {
    projectId: string;
    clientIp: string;
    endpoint: string;
    method: string;
    timestamp: string;
    rawBody?: string;
    slackWebhookUrl?: string;
    discordWebhookUrl?: string;
    attackVector: string;
    severity: string;
    summary: string;
}

/**
 * Asynchronously dispatches Slack Block Kit and Discord Embed alerts for CRITICAL / HIGH severity threats.
 * All HTTP exceptions are silently caught so webhook dispatching never blocks or crashes the audit worker lifecycle.
 */
export const sendWebhookAlerts = async (threat: ThreatNotificationPayload): Promise<void> => {
    const { severity, slackWebhookUrl, discordWebhookUrl, attackVector, summary, projectId, clientIp, endpoint, method } = threat;

    // Only dispatch alerts for HIGH and CRITICAL severity threats
    if (severity !== 'CRITICAL' && severity !== 'HIGH') {
        return;
    }

    // 1. Dispatch Slack Block Kit Alert
    if (slackWebhookUrl && slackWebhookUrl.trim() !== '') {
        try {
            const slackPayload = {
                text: `🚨 [AegisGate ${severity} Alert] ${attackVector} detected on ${endpoint}`,
                blocks: [
                    {
                        type: 'header',
                        text: {
                            type: 'plain_text',
                            text: `🛡️ AegisGate ${severity} Security Alert`,
                            emoji: true
                        }
                    },
                    {
                        type: 'section',
                        fields: [
                            { type: 'mrkdwn', text: `*Severity:*\n\`${severity}\`` },
                            { type: 'mrkdwn', text: `*Attack Vector:*\n\`${attackVector}\`` },
                            { type: 'mrkdwn', text: `*Project ID:*\n\`${projectId}\`` },
                            { type: 'mrkdwn', text: `*Client IP:*\n\`${clientIp}\`` },
                            { type: 'mrkdwn', text: `*Target Endpoint:*\n\`${method} ${endpoint}\`` }
                        ]
                    },
                    {
                        type: 'section',
                        text: {
                            type: 'mrkdwn',
                            text: `*AI Threat Intelligence Summary:*\n${summary}`
                        }
                    }
                ]
            };

            await axios.post(slackWebhookUrl, slackPayload, {
                headers: { 'Content-Type': 'application/json' },
                timeout: 5000
            });
            console.log(`📣 [Slack Alert Sent] Dispatched ${severity} notification for project ${projectId}`);
        } catch (error: any) {
            console.error('[Slack Webhook Dispatch Exception - Silently Bypassed]:', error?.message || error);
        }
    }

    // 2. Dispatch Discord Embed Card Alert
    if (discordWebhookUrl && discordWebhookUrl.trim() !== '') {
        try {
            const colorCode = severity === 'CRITICAL' ? 15158332 : 15105570; // Red or Orange
            const discordPayload = {
                username: 'AegisGate Security Shield',
                embeds: [
                    {
                        title: `🚨 AegisGate ${severity} Threat Alert`,
                        description: summary,
                        color: colorCode,
                        fields: [
                            { name: 'Severity', value: severity, inline: true },
                            { name: 'Attack Vector', value: attackVector, inline: true },
                            { name: 'Project ID', value: projectId, inline: true },
                            { name: 'Client IP', value: clientIp, inline: true },
                            { name: 'Endpoint', value: `${method} ${endpoint}`, inline: true }
                        ],
                        timestamp: new Date().toISOString()
                    }
                ]
            };

            await axios.post(discordWebhookUrl, discordPayload, {
                headers: { 'Content-Type': 'application/json' },
                timeout: 5000
            });
            console.log(`📣 [Discord Alert Sent] Dispatched ${severity} notification for project ${projectId}`);
        } catch (error: any) {
            console.error('[Discord Webhook Dispatch Exception - Silently Bypassed]:', error?.message || error);
        }
    }
};
