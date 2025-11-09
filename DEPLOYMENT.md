# PR-Agent Production Deployment Guide

## Quick Fix for Google GenAI Error

The error you're seeing:
```
Google Gen AI native provider not available, to install: uv add "crewai[google-genai]"
```

### Solution

**Install the correct CrewAI package with Google GenAI support:**

```bash
pip install "crewai[google-genai]>=0.36.0"
```

### Complete Production Setup

1. **Install all dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set environment variables:**
   ```bash
   export GITHUB_TOKEN="your_github_token"
   export GOOGLE_API_KEY="your_google_api_key"
   ```
   
   Or create a `.env` file:
   ```
   GITHUB_TOKEN=your_github_token
   GOOGLE_API_KEY=your_google_api_key
   ```

3. **Verify installation:**
   ```bash
   ./check_dependencies.sh
   ```

4. **Test the application:**
   ```bash
   python -m src.pr_agent.main --help
   ```

### For Hosting Platforms (Render/Railway/etc.)

1. **Update your `requirements.txt`** to include:
   ```
   crewai[google-genai]>=0.36.0
   ```

2. **Set environment variables** in your hosting platform:
   - `GITHUB_TOKEN`: Your GitHub personal access token
   - `GOOGLE_API_KEY`: Your Google AI API key

3. **Deploy with the updated requirements**

### Environment Variables Required

- **GITHUB_TOKEN**: GitHub personal access token with repo access
- **GOOGLE_API_KEY**: Google AI Studio API key

### Health Check

After deployment, check:
```bash
curl your-app-url/health
```

Should return:
```json
{
  "status": "ok",
  "dependencies_available": true,
  "missing_dependencies": [],
  "mode": "production"
}
```

### Troubleshooting

1. **If you still get the error**: Reinstall crewai with the google-genai extra:
   ```bash
   pip uninstall crewai
   pip install "crewai[google-genai]>=0.36.0"
   ```

2. **If API key issues**: Ensure GOOGLE_API_KEY is set and valid

3. **If GitHub access issues**: Ensure GITHUB_TOKEN has appropriate permissions