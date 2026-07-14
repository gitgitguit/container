/**
 * Enhanced Email Service Utilities
 * 
 * Provides email sending capabilities with nodemailer integration.
 * Used alongside EmailBasedMFA for magic links, API keys, and test emails.
 */

const nodemailer = require('nodemailer');

class EmailService {
    constructor(smtpConfig = {}) {
        this.smtpConfig = {
            host: smtpConfig.host || process.env.SMTP_HOST || 'localhost',
            port: parseInt(smtpConfig.port || process.env.SMTP_PORT || '25', 10),
            secure: smtpConfig.secure === true || smtpConfig.secure === 'true',
            auth: smtpConfig.user ? {
                user: smtpConfig.user || process.env.SMTP_USER,
                pass: smtpConfig.pass || process.env.SMTP_PASS
            } : undefined
        };

        this.fromEmail = smtpConfig.from || process.env.SMTP_FROM || 'noreply@proxy.local';
        this.transporter = this._initializeTransport();
    }

    _initializeTransport() {
        try {
            return nodemailer.createTransport(this.smtpConfig);
        } catch (err) {
            console.warn('[EmailService] Failed to initialize mail transport:', err.message);
            return null;
        }
    }

    /**
     * Send magic link for email-based authentication
     * User clicks link → automatic verification (no manual code entry)
     */
    async sendMagicLink(email, magicLink, options = {}) {
        if (!this.transporter) {
            throw new Error('Mail transporter not available');
        }

        try {
            const expiryMinutes = options.expiryMinutes || 15;
            const action = options.action || 'verify your account';
            const actionTitle = options.actionTitle || 'Verify Account';

            const html = `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #f9f9f9; padding: 20px; border-radius: 8px;">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <h2 style="color: #333; margin: 0;">🔐 M7 Proxy Authentication</h2>
                    </div>
                    
                    <div style="background: white; padding: 20px; border-radius: 6px; border-left: 4px solid #007bff;">
                        <p style="font-size: 16px; color: #333; margin-bottom: 20px;">
                            Click the link below to ${action}:
                        </p>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="${magicLink}" style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold; font-size: 16px;">
                                ${actionTitle}
                            </a>
                        </div>
                        
                        <p style="color: #666; font-size: 12px; margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee;">
                            <strong>Link expires in ${expiryMinutes} minutes.</strong>
                        </p>
                        
                        <p style="color: #999; font-size: 11px; margin: 10px 0;">
                            Or copy and paste this link in your browser:
                        </p>
                        
                        <p style="background: #f4f4f4; padding: 10px; border-radius: 4px; word-break: break-all; font-size: 12px; font-family: monospace; color: #666;">
                            ${magicLink}
                        </p>
                        
                        <p style="color: #d00; font-size: 12px; margin-top: 15px;">
                            <strong>⚠️ If you didn't request this link, please ignore this email or contact support.</strong>
                        </p>
                    </div>
                </div>
            `;

            const result = await this.transporter.sendMail({
                from: this.fromEmail,
                to: email,
                subject: `M7 Proxy - ${actionTitle}`,
                html
            });

            console.log(`[EMAIL] Magic link sent to ${email} (messageId: ${result.messageId})`);
            return { success: true, messageId: result.messageId };
        } catch (err) {
            console.error(`[EMAIL] Failed to send magic link to ${email}:`, err.message);
            throw err;
        }
    }

    /**
     * Send API Key with secure display (after verification)
     */
    async sendAPIKey(email, apiKey, expiresIn, options = {}) {
        if (!this.transporter) {
            throw new Error('Mail transporter not available');
        }

        try {
            const accessToken = options.accessToken
                ? `<p><strong>Access token:</strong> <code style="background: #f4f4f4; padding: 2px 6px; border-radius: 3px;">${options.accessToken}</code></p>`
                : '';

            const logoutUrl = options.logoutUrl
                ? `<p><a href="${options.logoutUrl}" style="color: #d00;">Revoke access now</a></p>`
                : '';

            const html = `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2>M7 Proxy API Key</h2>
                    <p>Your new API key has been generated:</p>
                    <p style="font-family: monospace; background: #f4f4f4; padding: 12px; word-break: break-all; border-radius: 4px; border-left: 4px solid #007bff;">${apiKey}</p>
                    <p><strong>Expires in:</strong> ${expiresIn}</p>
                    ${accessToken}
                    ${logoutUrl}
                    <p style="color: #d00; font-weight: bold;"><strong>⚠️ Save this key securely. You won't be able to see it again.</strong></p>
                    <p>Use this key in your API requests:</p>
                    <p style="font-family: monospace; background: #f4f4f4; padding: 12px; border-radius: 4px;">X-API-Key: ${apiKey}</p>
                </div>
            `;

            const result = await this.transporter.sendMail({
                from: this.fromEmail,
                to: email,
                subject: 'Your M7 Proxy API Key',
                html
            });

            console.log(`[EMAIL] API key sent to ${email} (messageId: ${result.messageId})`);
            return { success: true, messageId: result.messageId };
        } catch (err) {
            console.error(`[EMAIL] Failed to send API key to ${email}:`, err.message);
            throw err;
        }
    }

    /**
     * Send SMTP test email (for configuration validation)
     */
    async sendTestEmail({ host, port, secure, user, pass, from, to }) {
        const testTransport = nodemailer.createTransport({
            host,
            port: Number(port),
            secure: secure === true || secure === 'true',
            auth: user ? { user, pass } : undefined
        });

        try {
            const result = await testTransport.sendMail({
                from: from || process.env.SMTP_FROM || 'noreply@proxy.local',
                to,
                subject: 'LAN Proxy SMTP Test',
                text: 'LAN Proxy registration flow SMTP test succeeded.',
                html: `
                    <div style="font-family: Arial, sans-serif;">
                        <h2>SMTP Test Successful</h2>
                        <p>Your LAN Proxy email configuration is working correctly.</p>
                        <p><strong>Timestamp:</strong> ${new Date().toISOString()}</p>
                    </div>
                `
            });
            console.log(`[EMAIL] Test email delivered to ${to} (messageId: ${result.messageId})`);
            return { success: true, messageId: result.messageId };
        } catch (err) {
            console.error(`[EMAIL] Test email failed:`, err.message);
            throw err;
        } finally {
            await testTransport.close();
        }
    }
}

module.exports = EmailService;

