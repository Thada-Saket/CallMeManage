# Python virtual environment, packages and database migrations (sourced by install_service.sh).

install_backend() {
    step "Python packages (.venv)"
    [[ -f "$PROJECT_ROOT/requirements.txt" ]] || die "requirements.txt is missing"
    if [[ -x "$VENV_DIR/bin/python" ]]; then
        skip ".venv exists"
    else
        todo "create .venv"
        run as_app_user "python3 -m venv '$VENV_DIR'"
    fi
    # pip skips anything already installed at the pinned version ("Requirement already satisfied")
    todo "pip install -r requirements.txt"
    run as_app_user "'$VENV_DIR/bin/python' -m pip install --quiet --upgrade pip && '$VENV_DIR/bin/python' -m pip install --quiet -r '$PROJECT_ROOT/requirements.txt'"
}

migrate_database() {
    step "Database schema (alembic upgrade head)"
    run as_app_user "cd '$PROJECT_ROOT' && '$VENV_DIR/bin/alembic' upgrade head"
}
