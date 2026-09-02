import { createRoot } from "react-dom/client";

import App from "./App";
import "./styles/_base.scss";

const rootElement = document.getElementById("root");
if (!rootElement) throw new Error("Root element not found");
createRoot(rootElement).render(<App />);
