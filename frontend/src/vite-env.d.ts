/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Address of the backend API. Default: http://127.0.0.1:8000 */
  readonly VITE_API_URL?: string;
}
