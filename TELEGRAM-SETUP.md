# Telegram Login + Admin Approval Setup

This version uses Telegram as the approval source, so no PostgreSQL database is required.

## 1. Create a Telegram bot

1. Open `@BotFather` in Telegram.
2. Send `/newbot` and finish the bot creation.
3. Keep the bot username and token private.
4. Send `/setdomain` to BotFather, choose the bot, and enter your Railway domain without a path:

   `email-extraction-cmh9-production.up.railway.app`

Never commit the bot token or send it in chat.

## 2. Create the private approval group

1. Create a private Telegram group.
2. Add your bot to the group.
3. Promote the bot to administrator so `getChatMember` can verify users reliably.
4. Create an invite link that requires admin approval and save the link.

## 3. Find the private group chat ID

1. Send a message in the private group after adding the bot.
2. In your own browser, open:

   `https://api.telegram.org/botYOUR_TOKEN/getUpdates`

3. Find `chat.id` for the group. Private supergroup IDs usually begin with `-100`.
4. Do not share the URL or token. If the token was exposed, revoke it with BotFather and generate a new one.

## 4. Add Railway variables

Open Railway → your service → Variables, then add:

```env
TELEGRAM_BOT_TOKEN=the-token-from-BotFather
TELEGRAM_BOT_USERNAME=YourBotUsername
TELEGRAM_APPROVAL_CHAT_ID=-1001234567890
TELEGRAM_JOIN_URL=https://t.me/+your-private-approval-link
```

Keep the existing variables:

```env
NODE_ENV=production
MAX_EXTRACTION_LIMIT=100
SESSION_SECRET=your-existing-64-character-secret
```

`TELEGRAM_BOT_USERNAME` must not include `@`. Do not replace `SESSION_SECRET` after users sign in, because replacing it invalidates encrypted login cookies.

## 5. Deploy and test

1. Redeploy the Railway service.
2. Confirm `/api/health` shows `version: "7.0.1"` and `telegramConfigured: true`.
3. Open the application in a private browser window.
4. Sign in with Telegram.
5. A user who is not in the group sees “Waiting for admin approval”.
6. Approve the join request in Telegram.
7. The user clicks “Check approval” and enters the application.

Approved users receive a signed 30-day login cookie. Group membership is rechecked periodically. Removing a user from the private group revokes access after the next membership check.
