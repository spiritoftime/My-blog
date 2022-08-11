from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, Userform, LoginForm, CommentForm
from flask_gravatar import Gravatar
import os
from dotenv import load_dotenv
load_dotenv(r"C:\Users\Lenovo-L340\PycharmProjects\day 69\.env")
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("APP_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()

login_manager.init_app(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)



#
uri = os.environ.get("DB_URL")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)

# rest of connection code using the connection string `uri`
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(uri, "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES
# parent table here is user as parent table is the one that can have many childs

# back_populates means that you will link two attributes together. take note that back_populates will never show up
# as columns in sqlite!!
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=True)
    name = db.Column(db.String(250), nullable=True)
    posts = relationship("BlogPost", back_populates='author')
    comments = relationship('Comment', back_populates='comment_author')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship('User', back_populates='posts')
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comment_author = relationship('User', back_populates='comments')







# db.create_all()




@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user_data = User.query.filter_by(email=login_form.email.data).first()
        if user_data:
            if check_password_hash(user_data.password, login_form.password.data):
                login_user(user_data)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Wrong password!')
                return redirect(url_for('login'))
        else:
            flash('Wrong Email!')
            return redirect(url_for('login'))

    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET','POST'])
def show_post(post_id):
    comment = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    all_comments = Comment.query.all()
    if comment.validate_on_submit():
        if not current_user.is_authenticated:
            flash('Please login first')
            return redirect(url_for('login'))
        else:
            new_comment = Comment(
                text=comment.comment.data,
                author_id=current_user.id,)
            db.session.add(new_comment)
            db.session.commit()
    return render_template("post.html", post=requested_post, form=comment, all_comments=all_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


def admin_only(function):
    # you need args and kwargs because edit_post and delete_post require post_id as input. you could remove kwargs,
    # but just add it in case you need to add others next time
    def wrapper(*args, **kwargs):
        if not current_user.id:
            return abort(403)
        elif current_user.id == 1:
            return function(*args, **kwargs)
    # if you get some mapping error, change the name
    wrapper.__name__ = function.__name__
    return wrapper


@app.route("/new-post", methods=['GET','POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)



@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@admin_only
@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    user_form = Userform()
    if user_form.validate_on_submit():
        user_data = User.query.filter_by(email=user_form.email.data).first()
        if not user_data:
            hashed_password = generate_password_hash(user_form.password.data, salt_length=8, method='pbkdf2:sha256')
            new_user = User(
                password=hashed_password,
                email=user_form.email.data,
                name=user_form.name.data,
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        else:
            flash('You have already created an account before. Please login instead!')
            return redirect(url_for('login'))

    return render_template('register.html', form=user_form)



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
