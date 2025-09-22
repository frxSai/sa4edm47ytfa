# Vercel Deployment Guide

## Prerequisites
1. Install Vercel CLI: `npm i -g vercel` or `pnpm i -g vercel`
2. Create a Vercel account at https://vercel.com
3. Have your code in a Git repository (GitHub, GitLab, or Bitbucket)

## Environment Variables
Before deploying, set up environment variables in Vercel:

1. Go to your Vercel dashboard
2. Create a new project or go to your existing project settings
3. Navigate to Settings > Environment Variables
4. Add these environment variables:
   - `SECRET_PASSWORD`: Your secret password for regular users (e.g., "my_super_secret_password")
   - `ADMIN_KEY`: Your admin key for accessing logs (e.g., "admin_key_12345")

**Important:** These environment variables are required for the application to work properly in production.

## Deployment Steps

### Option 1: Using Vercel CLI (Recommended)
1. Open terminal in your project directory
2. Login to Vercel: `vercel login`
3. Deploy to preview: `vercel`
4. Follow the prompts to link/create your project
5. Deploy to production: `vercel --prod`

### Option 2: Using Git Integration (Automatic)
1. Push your code to GitHub/GitLab/Bitbucket
2. Go to Vercel dashboard and click "New Project"
3. Import your repository
4. Configure environment variables in the deployment settings
5. Deploy - Vercel will automatically deploy on every push to main branch

## Local Development
To run the app locally for development:
```bash
# Copy environment file and set your variables
cp .env.example .env

# Edit .env file with your actual values
# SECRET_PASSWORD=your_local_secret
# ADMIN_KEY=your_local_admin_key

# Run development server
python dev_server.py
```

## Important Notes for Vercel Deployment

### Serverless Limitations
- **Sessions**: Session data is stored in memory and will reset on each serverless function cold start
- **Logs**: File-based logs are not persistent across function invocations
- **Rate Limiting**: In-memory rate limiting will reset between function calls

### Recommended Production Improvements
For a production deployment, consider these enhancements:
1. **External Session Storage**: Use Redis or a database for session persistence
2. **External Logging**: Use external logging services (e.g., Vercel Analytics, Sentry, or CloudWatch)
3. **Database**: Store logs and rate limiting data in PostgreSQL, MongoDB, or similar
4. **CDN**: Static files are automatically served by Vercel's CDN

### Security Considerations
- Environment variables are securely stored in Vercel
- HTTPS is automatically enabled
- Security headers are configured in the application
- Rate limiting works within individual function executions

## File Structure for Vercel
```
fastapi_secret_app/
├── main.py              # Main FastAPI application (entry point)
├── dev_server.py        # Local development server
├── requirements.txt     # Python dependencies
├── runtime.txt          # Python version specification
├── vercel.json          # Vercel configuration
├── .env.example         # Environment variables template
├── .env                 # Local environment variables (not committed)
├── static/              # Static files (served by Vercel CDN)
│   └── music/           # Music files
├── templates/           # Jinja2 templates
├── logs/                # Local logs (not persistent on Vercel)
└── DEPLOYMENT.md        # This file
```

## Vercel Configuration Details

The `vercel.json` file is configured to:
- Use Python runtime for the main application
- Serve static files directly through Vercel's CDN
- Set appropriate function timeout limits
- Route all traffic through the FastAPI application

## Monitoring and Debugging

### Health Check
The application includes a health check endpoint at `/health` that returns the deployment environment.

### Logs on Vercel
- Function logs are available in the Vercel dashboard
- Real-time logs can be viewed during deployment
- Use `vercel logs [deployment-url]` to view logs via CLI

### Common Issues
1. **Environment Variables**: Ensure all required env vars are set in Vercel dashboard
2. **Static Files**: Verify static files are in the `static/` directory
3. **Dependencies**: Check that all Python packages are listed in `requirements.txt`
4. **Python Version**: Ensure `runtime.txt` specifies a supported Python version

## Post-Deployment Testing
1. Test login with your `SECRET_PASSWORD`
2. Test admin access with your `ADMIN_KEY`
3. Verify static files are loading correctly
4. Check the `/health` endpoint for status

## URLs After Deployment
- Login page: `https://your-app.vercel.app/`
- Main page: `https://your-app.vercel.app/main` (after login)
- Admin logs: `https://your-app.vercel.app/logs` (admin only)
- Health check: `https://your-app.vercel.app/health`
├── templates/           # Jinja2 templates
│   ├── login.html
│   ├── main.html
│   └── logs.html
└── .gitignore
```

## Security Considerations
- Make sure to set strong values for SECRET_PASSWORD and ADMIN_KEY
- The app includes rate limiting, but consider additional DDoS protection
- Sessions are stored in memory - for production, use Redis or database storage
- All sensitive data should be in environment variables, not in code
