# Render Deployment Configuration

## Environment Variables to Set on Render

Set these in the Render dashboard under Environment Variables:

### Database (PostgreSQL)
```
DATABASE_URL=postgresql://username:password@host.region.postgres.render.com:5432/dbname
```
- Get this from Render's PostgreSQL database connection details
- Format: `postgresql://user:password@host:port/database`

### Frontend Configuration
```
FRONTEND_URL=https://majorpr.netlify.app
```

### CORS Origins
```
ALLOWED_ORIGINS=https://majorpr.netlify.app,https://www.majorpr.netlify.app,http://localhost:3000,http://localhost:5173
```

### Security Keys (Generate new secure random values)
```
SECRET_KEY=<generate-new-secure-random-string>
JWT_SECRET=<generate-new-secure-random-string>
```

### Optional: Rate Limiting Storage (Production)
```
REDIS_URL=redis://default:password@host:port
```
- Leave empty to use in-memory storage (not recommended for production)
- If using Render Redis: Get from Render Redis database details

### Flask Environment
```
FLASK_ENV=production
```

## Critical Fixes Applied

1. ✅ **Database Connection**: Fixed psycopg2 URL parsing
   - Parses DATABASE_URL and extracts individual parameters
   - Handles PostgreSQL URL scheme validation

2. ✅ **CORS Configuration**: 
   - Added proper frontend URL handling
   - Added FRONTEND_URL environment variable support
   - Includes Content-Type and Authorization headers

3. ✅ **Rate Limiter**:
   - Configured to use Redis if REDIS_URL is set
   - Falls back to memory:// for development

4. ✅ **Security Backdoors Removed**:
   - Removed 'duo' username bypass in face authentication
   - Removed 'duo' username bypass in fingerprint authentication

## Testing Before Deployment

1. Test locally with Render PostgreSQL:
   ```bash
   DATABASE_URL=postgresql://... python app_enhanced.py
   ```

2. Verify CORS headers are sent:
   ```bash
   curl -H "Origin: https://majorpr.netlify.app" -v https://majorproject-itcj.onrender.com/api/register
   ```

3. Check logs for connection errors:
   ```bash
   # Render CLI
   render logs
   ```

## Troubleshooting

- **"invalid integer value "port" for connection option "port""**: Database URL missing port number
  - Use format: `postgresql://user:password@host:5432/db`

- **CORS errors**: Verify FRONTEND_URL and ALLOWED_ORIGINS are set correctly

- **Rate limiting warnings**: Redis not configured (normal for development, add Redis for production)
