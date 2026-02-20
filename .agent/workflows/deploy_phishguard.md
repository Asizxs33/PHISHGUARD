---
description: Deploy PhishGuard AI (Backend on Render, Frontend on Netlify)
---

### 1. Preparation (GitHub)

1.  **Push your code to GitHub**:
    Ensure your project is in a GitHub repository.
    The structure should be:
    ```
    /
    ├── backend/
    ├── frontend/
    └── ...
    ```

### 2. Backend Deployment (Render.com)

1.  Log in to [Render.com](https://render.com/).
2.  Click **New +** -> **Web Service**.
3.  Connect your GitHub repository.
4.  Configure the service:
    *   **Name**: `phishguard-backend` (or similar)
    *   **Root Directory**: `backend`
    *   **Runtime**: `Docker`
    *   **Region**: Frankfurt (or closest to you)
    *   **Instance Type**: Free
5.  **Environment Variables**:
    *   Key: `RENDER`
    *   Value: `true`
    *   *(Optional)* Key: `PORT`, Value: `10000`
6.  Click **Create Web Service**.
7.  Wait for the build to finish. It might take 5-10 minutes because it will train the ML models during the build.
8.  **Copy the Backend URL**: Once deployed, copy the URL (e.g., `https://phishguard-backend.onrender.com`). You will need it for the frontend.

### 3. Frontend Deployment (Netlify)

1.  Log in to [Netlify](https://www.netlify.com/).
2.  Click **Add new site** -> **Import from existing project**.
3.  Connect via **GitHub** and select your repository.
4.  Configure the build settings:
    *   **Base directory**: `frontend`
    *   **Build command**: `npm run build`
    *   **Publish directory**: `dist`
5.  **Environment Variables** (Click "Add environment variable"):
    *   Key: `VITE_API_URL`
    *   Value: `https://phishguard-backend.onrender.com` (The URL you copied from Render)
6.  Click **Deploy PhishGuard**.

### 4. Verification

1.  Open your deployed Netlify URL.
2.  Try analyzing a URL or Email.
3.  Ensure the "Confidence" is showing (it should be calculated correctly now).
