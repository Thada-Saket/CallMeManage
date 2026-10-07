import { Navigate, Route, Routes, useSearchParams } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import ToastContainer from "./components/ToastContainer";
import Login from "./pages/Login";
import Devices from "./pages/Devices";
import DeviceDetail from "./pages/DeviceDetail";
import CliGenerator from "./pages/CliGenerator";
import Sites from "./pages/Sites";
import AccountSettings from "./pages/AccountSettings";
import RunningConfigurationViewer from "./pages/RunningConfigurationViewer";
import AsciiInputGuard from "./components/AsciiInputGuard";
import SiteAccessGate from "./components/SiteAccessGate";
import "./App.css";
import "./assets/css/mobile.css";

function LoginRoute() {
  const { isAuthenticated } = useAuth();
  if (isAuthenticated) return <Navigate to="/sites" replace />;
  return <Login />;
}

function RequireSiteId({ children }) {
  const [searchParams] = useSearchParams();
  return searchParams.get("site_id") ? children : <Navigate to="/sites" replace />
}

function App() {
  return (
    <SiteAccessGate>
      <AuthProvider>
        <AsciiInputGuard />
        <Routes>
        <Route path="/login" element={<LoginRoute />} />
        <Route
          path="/devices"
          element={
            <ProtectedRoute>
              <RequireSiteId>
                <Devices />
              </RequireSiteId>
            </ProtectedRoute>
          }
        />
        <Route
          path="/devices/:devId/running-configuration/:snapshotId"
          element={
            <ProtectedRoute>
              <RunningConfigurationViewer />
            </ProtectedRoute>
          }
        />
        <Route
          path="/devices/:devId"
          element={
            <ProtectedRoute>
              <DeviceDetail />
            </ProtectedRoute>
          }
        />
        <Route
          path="/cli-generate"
          element={
            <ProtectedRoute>
              <RequireSiteId>
                <CliGenerator />
              </RequireSiteId>
            </ProtectedRoute>
          }
        />
        <Route
          path="/sites"
          element={
            <ProtectedRoute>
              <Sites />
            </ProtectedRoute>
          }
        />
        <Route
          path="/account"
          element={
            <ProtectedRoute>
              <AccountSettings />
            </ProtectedRoute>
          }
        />
        <Route path="*" element={<Navigate to="/sites" replace />} />
        </Routes>
        <ToastContainer />
      </AuthProvider>
    </SiteAccessGate>
  );
}

export default App;
