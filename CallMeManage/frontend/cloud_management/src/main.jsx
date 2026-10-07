import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import './index.css'
import App from './App.jsx'
import { APP_BASE_PATH } from './utils/appBase.js'

const routerBase = APP_BASE_PATH === "/"
  ? undefined
  : APP_BASE_PATH.replace(/\/$/, "");

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <BrowserRouter basename={routerBase}>
      <App />
    </BrowserRouter>
  </StrictMode>,
)
