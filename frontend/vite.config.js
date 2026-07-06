import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  server: {
    port: 5173,
    allowedHosts: ['frontend', 'localhost', '127.0.0.1'],
    proxy: {
      '/api': { target: 'http://backend:8000', changeOrigin: true },
    },
  },
})
