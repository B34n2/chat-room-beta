import re
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from extensions import db
from models import User, Channel, Message, Friend
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123@localhost/chatroom'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'beansisthebest'

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

migrate = Migrate(app, db)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def is_valid_password(password):
    # Minimum 8 characters
    if len(password) < 8:
        return False

    # At least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False

    # At least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False

    # At least one digit
    if not re.search(r'\d', password):
        return False

    return True

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user is not None and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.')
        elif User.query.filter_by(username=username).first():
            flash('Username is already taken.')
        else:
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully.')
            return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/friends/request', methods=['POST'])
@login_required
def request_friend():
    friend_id = request.form.get('friend_id')
    if not friend_id:
        flash('Friend ID not provided')

    friend = User.query.get(friend_id)
    if not friend:
        flash('User not found')

    friend_request = Friend(user1=current_user, user2=friend, accepted=False)
    db.session.add(friend_request)
    db.session.commit()

    flash('Friend request sent')
    return redirect(url_for('friends_list'))

@app.route('/friends/accept', methods=['POST'])
@login_required
def accept_friend_request():
    friend_id = request.form.get('friend_id')
    if not friend_id:
        flash("Friend ID not provided")
        return redirect(url_for('friends_list'))

    friend_request = Friend.query.filter_by(user1_id=friend_id, user2_id=current_user.id, accepted=False).first()
    if not friend_request:
        flash("Friend request not found")
        return redirect(url_for('friends_list'))

    if current_user.id != friend_request.user2_id:
        flash("You are not authorized to accept this friend request")
        return redirect(url_for('friends_list'))

    friend_request.accepted = True
    db.session.commit()

    flash("Friend request accepted")
    return redirect(url_for('friends_list'))


@app.route('/friends/decline', methods=['POST'])
@login_required
def decline_friend_request():
    friend_id = request.form.get('friend_id')
    if not friend_id:
        flash('Friend ID not provided')

    friend_request = Friend.query.filter_by(user1_id=friend_id, user2_id=current_user.id, accepted=False).first()
    if not friend_request:
        flash('Friend request not found')

    db.session.delete(friend_request)
    db.session.commit()

    flash('Friend request declined')
    return redirect(url_for('friends_list'))

@app.route('/friends/remove', methods=['POST'])
@login_required
def remove_friend():
    friend_id = request.form.get('friend_id')
    if not friend_id:
        flash('Friend ID not provided')

    friendship = Friend.query.filter(
        (Friend.user1_id == current_user.id) & (Friend.user2_id == friend_id) |
        (Friend.user1_id == friend_id) & (Friend.user2_id == current_user.id)
    ).first()

    if not friendship:
        flash('Friendship not found')

    db.session.delete(friendship)
    db.session.commit()

    flash('Friend removed successfully')
    return redirect(url_for('friends_list'))

@app.route('/dashboard')
@login_required
def dashboard():

    return render_template('dashboard.html')

@app.route('/messages/send', methods=['POST'])
@login_required
def send_message():
    receiver_id = request.form.get('receiver_id')
    content = request.form.get('content')

    if not receiver_id or not content:
        flash("Both receiver ID and content are required")
        return redirect(url_for('get_messages', friend_id=receiver_id))

    message = Message(sender_id=current_user.id, receiver_id=receiver_id, content=content)
    db.session.add(message)
    db.session.commit()

    flash("Message sent")
    return redirect(url_for('get_messages', friend_id=receiver_id))

@app.route('/messages/<int:friend_id>')
@login_required
def get_messages(friend_id):
    messages = Message.query.filter(
        (Message.sender_id == current_user.id) & (Message.receiver_id == friend_id) |
        (Message.sender_id == friend_id) & (Message.receiver_id == current_user.id)
    ).order_by(Message.timestamp.asc()).all()

    friend = User.query.get(friend_id)

    return render_template('messages.html', messages=messages, friend=friend)

@app.route('/friends_list')
@login_required
def friends_list():
    friendships = Friend.query.filter(
        (Friend.user1_id == current_user.id) | (Friend.user2_id == current_user.id),
        Friend.accepted == True
    ).all()

    friend_requests = Friend.query.filter_by(user2_id=current_user.id, accepted=False).all()

    friends = []
    for friendship in friendships:
        friend = friendship.user1 if friendship.user2_id == current_user.id else friendship.user2
        friends.append(friend)

    return render_template('friends_list.html', friends=friends, friend_requests=friend_requests)

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

def create_tables():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)