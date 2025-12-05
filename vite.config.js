import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const blockchainApiUrl = process.env.VITE_BLOCKCHAIN_API || 'http://localhost:5000';
const biometricApiUrl = process.env.VITE_API_URL || 'https://majorproject-itcj.onrender.com';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: blockchainApiUrl,
        changeOrigin: true,
        secure: false,
      },
      '/uploads': biometricApiUrl,
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
  define: {
    'process.env.VITE_API_URL': JSON.stringify(process.env.VITE_API_URL),
    'process.env.VITE_BLOCKCHAIN_API': JSON.stringify(process.env.VITE_BLOCKCHAIN_API),
  },
});
