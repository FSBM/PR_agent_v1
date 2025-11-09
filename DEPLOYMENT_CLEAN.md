# PR-Agent Production Deployment Guide

## Quick Fix for Current Production Issue

The error you're seeing:
```
Missing: crewai[google-genai]: No module named 'google.generativeai'
```

### Immediate Solution for Render/Railway/Other Hosting:

1. **Update your requirements.txt** in the production deployment to include:
   ```
   crewai[google-genai]>=0.36.0
   google-generativeai>=0.8.0
   ```

2. **Set ONLY these environment variables in production:**
   ```bash
   GITHUB_TOKEN=your_github_token_here
   GOOGLE_API_KEY=your_google_api_key_here
   CREWAI_TELEMETRY_OPT_OUT=true
   ENVIRONMENT=production
   ```

3. **Remove these OpenAI compatibility variables from production:**
   - ❌ Don't set `OPENAI_MODEL_NAME`
   - ❌ Don't set `OPENAI_API_BASE`  
   - ❌ Don't set `OPENAI_API_KEY`

   These interfere with CrewAI's native Google AI integration.

### Why This Fixes It:

1. **Explicit Google AI dependency**: Adding `google-generativeai>=0.8.0` ensures the package is installed
2. **Clean environment**: Removing OpenAI compatibility variables lets CrewAI use its native Google AI provider
3. **Proper model handling**: CrewAI will automatically use the correct Google AI models

### Complete Production Setup

1. **Install all dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set environment variables in your hosting platform:**
   - `GITHUB_TOKEN`: Your GitHub personal access token
   - `GOOGLE_API_KEY`: Your Google AI Studio API key
   - `CREWAI_TELEMETRY_OPT_OUT`: true
   - `ENVIRONMENT`: production

3. **Deploy with updated requirements.txt**

4. **Test the health endpoint:**
   ```bash
   curl your-production-url/health
   ```

### For Render Specifically:

In your Render dashboard:
1. Go to Environment
2. Add the 4 environment variables listed above
3. Redeploy

The deployment should now work without the `google.generativeai` import error.