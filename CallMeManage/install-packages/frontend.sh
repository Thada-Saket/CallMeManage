# Frontend packages (React, Vite, ...) (sourced by install.sh).
# The build itself is build_frontend in install-packages/service.sh.

install_frontend() {
    step "Frontend packages (npm ci: React, Vite, ...)"
    if [[ -d "$FRONTEND_DIR/node_modules" ]] && as_app_user "cd '$FRONTEND_DIR' && npm ls --depth=0 >/dev/null 2>&1"; then
        skip "node_modules matches package-lock.json"
    else
        todo "npm ci"
        run as_app_user "cd '$FRONTEND_DIR' && npm ci"
    fi
}
