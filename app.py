from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField, URLField, TextAreaField
from wtforms.validators import DataRequired, URL, NumberRange, Optional
import os

app = Flask(__name__)

# Database Configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "your_secret_key"

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ---------------- MODELS ----------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    mobile = db.Column(db.String(15), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)


class Movie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    genre = db.Column(db.String(50), nullable=False)
    release_year = db.Column(db.Integer, nullable=False)
    poster_url = db.Column(db.String(255), nullable=True)
    plot = db.Column(db.Text, nullable=True)  # New field for the story
    streaming_link = db.Column(db.String(255), nullable=True) 

class FavoriteMovie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    movie_id = db.Column(db.Integer, db.ForeignKey('movie.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('favorites', lazy=True, cascade="all, delete"))
    movie = db.relationship('Movie', backref=db.backref('favorites', lazy=True, cascade="all, delete"))

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    movie_id = db.Column(db.Integer, db.ForeignKey('movie.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Nullable for guest users
    username = db.Column(db.String(150), nullable=False)  # Store name for guests
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    movie = db.relationship('Movie', backref=db.backref('reviews', lazy=True, cascade="all, delete"))
    user = db.relationship('User', backref=db.backref('reviews', lazy=True, cascade="all, delete"), foreign_keys=[user_id])

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    movie_id = db.Column(db.Integer, db.ForeignKey('movie.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Nullable for guests
    username = db.Column(db.String(80), nullable=True)  # Guest users can have a name
    rating = db.Column(db.Integer, nullable=False)  # 1 to 5 stars

    movie = db.relationship('Movie', backref=db.backref('ratings', lazy=True))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------- FORMS ----------------
class AddMovieForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    genre = StringField('Genre', validators=[DataRequired()])
    release_year = IntegerField('Release Year', validators=[DataRequired()])
    poster_url = URLField('Poster URL', validators=[Optional(), URL()])
    plot = TextAreaField('Main Story (Plot)', validators=[Optional()])  # New field
    streaming_link = URLField('Streaming Link', validators=[Optional(), URL()])  # New field
    submit = SubmitField('Add Movie')


# ---------------- ADMIN SETUP ----------------
def create_admin():
    with app.app_context():
        db.create_all()
        admin_email = "admin@example.com"
        if not User.query.filter_by(email=admin_email).first():
            admin = User(
                name="Admin User",
                email=admin_email,
                mobile="1234567890",
                role="admin"
            )
            admin.set_password("adminpassword")
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin user created: Email - admin@example.com | Password - adminpassword")


create_admin()


# ---------------- ROUTES ----------------
@app.route("/")
def home():
    movies = Movie.query.all()
    return render_template("index.html", movies=movies)


@app.route("/dashboard")
@login_required
def dashboard():
    favorite_movies = FavoriteMovie.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", favorite_movies=favorite_movies)


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")

@app.route('/search')
def search():
    query = request.args.get('query', '').strip().lower()  # Get the search input
    if not query:
        return render_template('base.html', movies=[])

    movies = []  # Initialize an empty list for results

    # Check if query is a number (likely a year)
    if query.isdigit() and len(query) == 4:
        movies = Movie.query.filter(Movie.release_year == int(query)).all()

    # Check if query matches a genre
    elif query in ["action", "comedy", "drama", "thriller", "horror", "romance"]:  # Add more genres
        movies = Movie.query.filter(Movie.genre.ilike(f"%{query}%")).all()

    # Otherwise, assume it's a title search
    else:
        movies = Movie.query.filter(Movie.title.ilike(f"%{query}%")).all()

    return render_template('search_results.html', movies=movies, query=query)

@app.route('/search_live')
def search_live():
    query = request.args.get('query', '').strip().lower()
    
    if not query:
        return jsonify({'movies': []})

    movies = []

    # Search by release year if the query is a 4-digit number
    if query.isdigit() and len(query) == 4:
        movies = Movie.query.filter(Movie.release_year == int(query)).limit(5).all()

    # Search by genre
    elif db.session.query(Movie).filter(Movie.genre.ilike(f"%{query}%")).count() > 0:
        movies = Movie.query.filter(Movie.genre.ilike(f"%{query}%")).limit(5).all()

    # Search by movie title
    else:
        movies = Movie.query.filter(Movie.title.ilike(f"%{query}%")).limit(5).all()

    return jsonify({'movies': [{'id': movie.id, 'title': movie.title} for movie in movies]})

@app.route("/movie/<int:movie_id>")
def movie_detail(movie_id):
    movie = Movie.query.get_or_404(movie_id)
    reviews = Review.query.filter_by(movie_id=movie_id).order_by(Review.timestamp.desc()).all()
    avg_rating = db.session.query(db.func.avg(Rating.rating)).filter(Rating.movie_id == movie_id).scalar()
    avg_rating = round(avg_rating, 2) if avg_rating else "No ratings yet"
    return render_template("movie.html", movie=movie, reviews=reviews, avg_rating=avg_rating)


@app.route("/add_favorite/<int:movie_id>", methods=["POST"])
@login_required
def add_favorite(movie_id):
    movie = Movie.query.get_or_404(movie_id)

    if FavoriteMovie.query.filter_by(user_id=current_user.id, movie_id=movie_id).first():
        flash("Movie already in favorites!", "warning")
    else:
        new_favorite = FavoriteMovie(user_id=current_user.id, movie_id=movie.id)
        db.session.add(new_favorite)
        db.session.commit()
        flash("Movie added to favorites!", "success")

    return redirect(url_for("home"))


@app.route("/remove_favorite/<int:movie_id>", methods=["POST"])
@login_required
def remove_favorite(movie_id):
    favorite = FavoriteMovie.query.filter_by(user_id=current_user.id, movie_id=movie_id).first()
    if favorite:
        db.session.delete(favorite)
        db.session.commit()
        flash("Movie removed from favorites!", "success")
    else:
        flash("Movie not found in your favorites!", "danger")

    return redirect(url_for("dashboard"))


@app.route("/add_movie", methods=["GET", "POST"])
@login_required
def add_movie():
    if current_user.role != "admin":
        flash("You do not have permission to add movies!", "danger")
        return redirect(url_for("dashboard"))

    form = AddMovieForm()
    if form.validate_on_submit():
        new_movie = Movie(
            title=form.title.data,
            genre=form.genre.data,
            release_year=form.release_year.data,
            poster_url=form.poster_url.data,
            plot=form.plot.data,  # Save plot
            streaming_link=form.streaming_link.data
        )
        db.session.add(new_movie)
        db.session.commit()
        flash("Movie added successfully!", "success")
        return redirect(url_for("home"))

    return render_template("add_movie.html", form=form)


@app.route("/delete_movie/<int:movie_id>", methods=["POST"])
@login_required
def delete_movie(movie_id):
    movie = Movie.query.get_or_404(movie_id)

    # Allow admins to delete any movie
    if current_user.role == "admin" or movie.user_id == current_user.id:  
        db.session.delete(movie)
        db.session.commit()
        flash("Movie deleted successfully!", "success")
    else:
        flash("You can only delete your own movies!", "danger")

    return redirect(url_for("dashboard"))

@app.route("/add_review/<int:movie_id>", methods=["POST"])
def add_review(movie_id):
    movie = Movie.query.get_or_404(movie_id)

    # Handle both JSON and form requests
    if request.is_json:
        data = request.get_json()
        content = data.get("content", "").strip()
        username = current_user.name if current_user.is_authenticated else data.get("username")
    else:
        content = request.form.get("content", "").strip()
        username = current_user.name if current_user.is_authenticated else request.form.get("username")

    # Validate content
    if not content:
        return jsonify({"success": False, "error": "Review cannot be empty!"}), 400

    # Create and save review
    new_review = Review(
        movie_id=movie_id,
        user_id=current_user.id if current_user.is_authenticated else None,
        username=username,
        content=content
    )
    db.session.add(new_review)
    db.session.commit()

    return jsonify({"success": True, "username": username, "content": content})


@app.route('/rate_movie/<int:movie_id>', methods=['POST'])
def rate_movie(movie_id):
    data = request.json
    rating_value = int(data.get('rating', 0))

    if rating_value < 1 or rating_value > 5:
        return jsonify({'error': 'Invalid rating value'}), 400

    if current_user.is_authenticated:
        existing_rating = Rating.query.filter_by(movie_id=movie_id, user_id=current_user.id).first()
        if existing_rating:
            existing_rating.rating = rating_value
        else:
            new_rating = Rating(movie_id=movie_id, user_id=current_user.id, rating=rating_value)
            db.session.add(new_rating)
    else:
        username = data.get('username', 'Guest')
        existing_rating = Rating.query.filter_by(movie_id=movie_id, username=username).first()
        if existing_rating:
            existing_rating.rating = rating_value
        else:
            new_rating = Rating(movie_id=movie_id, username=username, rating=rating_value)
            db.session.add(new_rating)

    db.session.commit()

    avg_rating = db.session.query(db.func.avg(Rating.rating)).filter(Rating.movie_id == movie_id).scalar()

    return jsonify({'message': 'Rating submitted successfully', 'avg_rating': round(avg_rating, 2)})


# ---------------- AUTH ROUTES ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        mobile = request.form.get("mobile")
        role = request.form.get("role", "user")

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("register"))

        new_user = User(name=name, email=email, mobile=mobile, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password!", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

class UpdateMovieForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    genre = StringField("Genre", validators=[DataRequired()])
    release_year = IntegerField("Release Year", validators=[DataRequired(), NumberRange(min=1888, max=2100)])
    poster_url = StringField("Poster URL", validators=[DataRequired(), URL()])
    submit = SubmitField("Update Movie")

    class Meta:
        csrf = False  # Disable CSRF protection


@app.route("/update_movie/<int:movie_id>", methods=["GET", "POST"])
@login_required
def update_movie(movie_id):
    movie = Movie.query.get_or_404(movie_id)

    # Allow only admins to update any movie
    if current_user.role != "admin":
        flash("You do not have permission to update movies!", "danger")
        return redirect(url_for("home"))

    form = UpdateMovieForm(obj=movie)  # Pre-fill the form with existing movie data

    if form.validate_on_submit():
        movie.title = form.title.data
        movie.genre = form.genre.data
        movie.release_year = form.release_year.data  # Fixed field name
        movie.poster_url = form.poster_url.data
        db.session.commit()
        flash("Movie updated successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("update_movie.html", form=form, movie=movie)  # Pass form

#EEROR HANDLING
@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template("500.html"), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template("403.html"), 403


if __name__ == "__main__":
    app.run(debug=True) 