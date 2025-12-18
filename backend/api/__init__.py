from .auth_routes import bp as auth_bp
from .products import bp as products_bp
from .vulnerabilities import bp as vulns_bp
from .users import bp as users_bp

def register_api(app):
    app.register_blueprint(auth_bp)
    app.register_blueprint(products_bp)
    app.register_blueprint(vulns_bp)
    app.register_blueprint(users_bp)