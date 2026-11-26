#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User, UserSchema


class ClearSession(Resource):

    def delete(self):
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204


class Signup(Resource):

    def post(self):
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return {'error': 'Invalid request'}, 400

        username = data.get('username')
        password = data.get('password')

        if not isinstance(username, str) or not username.strip():
            return {'error': 'Username is required'}, 400

        if not isinstance(password, str) or not password:
            return {'error': 'Password is required'}, 400

        if len(password.encode('utf-8')) > 72:
            return {'error': 'Password is too long'}, 400

        existing_user = User.query.filter_by(
            username=username
        ).first()

        if existing_user:
            return {'error': 'Username already exists'}, 400

        user = User(username=username)
        user.password_hash = password

        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.id

        return UserSchema().dump(user), 201


class CheckSession(Resource):

    def get(self):
        user_id = session.get('user_id')

        if user_id is not None:
            user = db.session.get(User, user_id)

            if user:
                return UserSchema().dump(user), 200

        return {}, 204


class Login(Resource):

    def post(self):
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return {'error': 'Invalid request'}, 400

        username = data.get('username')
        password = data.get('password')

        if not isinstance(username, str):
            return {'error': 'Invalid username or password'}, 401

        user = User.query.filter_by(
            username=username
        ).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id

            return UserSchema().dump(user), 200

        return {'error': 'Invalid username or password'}, 401


class Logout(Resource):

    def delete(self):
        session.pop('user_id', None)

        return {}, 204


api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')


if __name__ == '__main__':
    app.run(port=5555, debug=True)