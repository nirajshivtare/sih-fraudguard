# FraudGuard AI - Deployment Guide

Since you are presenting this at SIH 2026, deploying the project so judges can test it live on the internet is a huge advantage. 

We have designed this project specifically to be deployed on **Free Tier** cloud services.

## 1. Backend Deployment (Render.com)

We will use [Render.com](https://render.com) because it natively supports Python FastAPI and is free.

1. Create a free account on Render.com.
2. Push this entire `SIH 2026` folder to a GitHub repository.
3. On Render, click **New +** -> **Blueprint**.
4. Connect your GitHub account and select your repository.
5. Render will automatically detect the `render.yaml` file I created in the root folder and configure the Python server for you.
6. Click **Apply**. 

*Wait about 5 minutes. Render will give you a live URL like `https://fraudguard-ai-backend.onrender.com`.*

## 2. Frontend Deployment (Vercel or Netlify)

Now that the backend is live on the internet, we need to host the `index.html` dashboard.

1. **Important Step First:** Open `frontend/app.js` and change the `fetch` URL on line 17 from `http://localhost:8000/api/v1/analyze-email` to your new Render backend URL (e.g., `https://fraudguard-ai-backend.onrender.com/api/v1/analyze-email`).
2. Go to [Vercel.com](https://vercel.com) or [Netlify.com](https://netlify.com) and create a free account.
3. Connect your GitHub repository.
4. When it asks for the "Root Directory", type `frontend`.
5. Click **Deploy**.

*Within 30 seconds, Vercel will give you a live website link (e.g., `https://fraudguard-dashboard.vercel.app`).*

---

**That's it!** You can now give the live Vercel URL to the SIH judges, and they can upload emails directly from their phones or laptops to test your AI.
