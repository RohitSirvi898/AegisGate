import axios from 'axios';

export interface WebhookAlertPayload {
  projectId: string;
  clientIp: string;
  path: string;
  method: string;
  status: number;
  rule?: string;
  summary?: string;
  body?: any;
  timestamp?: string;
  slackWebhookUrl?: string;
  discordWebhookUrl?: string;
}

const MAX_WEBHOOKS_PER_MINUTE = 5;
const WEBHOOK_WINDOW_MS = 60000;
const projectWebhookHistory = new Map<string, number[]>();

export function isWebhookRateLimited(projectId: string): boolean {
  const now = Date.now();
  const history = projectWebhookHistory.get(projectId) || [];
  const recent = history.filter(t => now - t < WEBHOOK_WINDOW_MS);

  if (recent.length >= MAX_WEBHOOKS_PER_MINUTE) {
    return true;
  }

  recent.push(now);
  projectWebhookHistory.set(projectId, recent);
  return false;
}

export function clearWebhookRateLimits(): void {
  projectWebhookHistory.clear();
}

// Neutralizes mentions and markdown code-block breakouts, truncating to max length
export function escapeWebhookContent(input?: any, maxLen = 500): string {
  if (input === undefined || input === null) {
    return '';
  }

  let text = typeof input === 'string' ? input : JSON.stringify(input);

  text = text.replace(/@(everyone|here)/gi, '@\u200b$1');
  text = text.replace(/<@&?\d+>/g, '[MENTION_REMOVED]');
  text = text.replace(/`/g, "'");
  text = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');

  if (text.length > maxLen) {
    text = text.slice(0, maxLen) + '...[TRUNCATED]';
  }

  return text;
}

export const sendWebhookAlerts = async (alert: WebhookAlertPayload): Promise<void> => {
  const { status, rule, projectId, slackWebhookUrl, discordWebhookUrl } = alert;

  const isHighSeverity = rule === 'request_blocked' || status === 403;
  if (!isHighSeverity) {
    return;
  }

  if (!slackWebhookUrl && !discordWebhookUrl) {
    return;
  }

  if (isWebhookRateLimited(projectId)) {
    console.warn(`⚠️ [Webhook Throttled] Rate limit (5/min) exceeded for project '${projectId}'. Skipping alert.`);
    return;
  }

  const safePath = escapeWebhookContent(alert.path, 500);
  const safeBody = escapeWebhookContent(alert.body, 500);
  const safeMethod = escapeWebhookContent(alert.method, 10);
  const safeIp = escapeWebhookContent(alert.clientIp, 45);
  const safeRule = escapeWebhookContent(rule || 'Security Filter Violation', 100);
  const safeSummary = escapeWebhookContent(
    alert.summary || `Request blocked by security rule: ${safeRule}`,
    500
  );

  if (slackWebhookUrl && slackWebhookUrl.trim() !== '') {
    try {
      const blocks: any[] = [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: '🛡️ AegisGate Security Alert',
            emoji: true
          }
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Status:*\n\`${status}\`` },
            { type: 'mrkdwn', text: `*Rule:*\n\`${safeRule}\`` },
            { type: 'mrkdwn', text: `*Project ID:*\n\`${projectId}\`` },
            { type: 'mrkdwn', text: `*Client IP:*\n\`${safeIp}\`` },
            { type: 'mrkdwn', text: `*Endpoint:*\n\`${safeMethod} ${safePath}\`` }
          ]
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*Security Threat Summary:*\n${safeSummary}`
          }
        }
      ];

      if (safeBody) {
        blocks.push({
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*Body Preview:*\n\`\`\`${safeBody}\`\`\``
          }
        });
      }

      await axios.post(
        slackWebhookUrl,
        {
          text: `🚨 [AegisGate Alert] ${safeRule} detected on ${safePath}`,
          blocks
        },
        {
          headers: { 'Content-Type': 'application/json' },
          timeout: 5000
        }
      );
      console.log(`📣 [Slack Alert Sent] Dispatched notification for project '${projectId}'`);
    } catch (error: any) {
      console.error('[Slack Webhook Error - Silently Bypassed]:', error?.message || error);
    }
  }

  if (discordWebhookUrl && discordWebhookUrl.trim() !== '') {
    try {
      const discordPayload = {
        username: 'AegisGate Security Shield',
        embeds: [
          {
            title: '🚨 AegisGate Threat Alert (403)',
            description: safeSummary,
            color: 15158332,
            fields: [
              { name: 'Status', value: String(status), inline: true },
              { name: 'Rule', value: safeRule, inline: true },
              { name: 'Project ID', value: projectId, inline: true },
              { name: 'Client IP', value: safeIp, inline: true },
              { name: 'Endpoint', value: `${safeMethod} ${safePath}`, inline: true }
            ],
            timestamp: new Date().toISOString()
          }
        ]
      };

      await axios.post(discordWebhookUrl, discordPayload, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 5000
      });
      console.log(`📣 [Discord Alert Sent] Dispatched notification for project '${projectId}'`);
    } catch (error: any) {
      console.error('[Discord Webhook Error - Silently Bypassed]:', error?.message || error);
    }
  }
};

export { sendWebhookAlerts as sendThreatAlert };
