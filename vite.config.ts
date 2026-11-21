import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

// Serves /.well-known/agent.json from public/agent.json in dev + preview,
// and emits it into dist/.well-known/ on build - no manual copy needed.
const wellKnown = (): Plugin => {
  const rewrite = (req: { url?: string }, _res: unknown, next: () => void) => {
    if (req.url && req.url.split('?')[0] === '/.well-known/agent.json') req.url = '/agent.json'
    next()
  }
  return {
    name: 'vouchweb-well-known',
    configureServer: (s) => void s.middlewares.use(rewrite),
    configurePreviewServer: (s) => void s.middlewares.use(rewrite),
    generateBundle() {
      this.emitFile({
        type: 'asset',
        fileName: '.well-known/agent.json',
        source: readFileSync(resolve(process.cwd(), 'public/agent.json'), 'utf8'),
      })
    },
  }
}

export default defineConfig({
  plugins: [react(), wellKnown()],
  server: { port: 5173 },
  build: { target: 'es2022' },
})
