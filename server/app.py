#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

@app.before_request
def check_if_logged_in():
    open_access_list = [
        "signup",
        "login",
        "check_session"
    ]
    
    if (request.endpoint) not in open_access_list and (not session.get("user_id")):
        return {"error": "401 Unauthorized"}, 401

class Signup(Resource):
    
    def post(self):
        
        data = request.get_json()
        
        username = data.get("username")
        password = data.get("password")
        image_url = data.get("image_url")
        bio = data.get("bio")
        
        if not username or not password or not image_url or not bio:
            return {"error": "All fields (username, password, image_url, bio) are required"}, 422
        
        user = User(
            username=username,
            image_url=image_url,
            bio=bio
        )
        
        # the setter will encrypt this
        user.password_hash = password
        
        try:
            db.session.add(user)
            db.session.commit()
            
            session["user_id"] = user.id
            
            return user.to_dict(), 201
        
        except IntegrityError:
            db.session.rollback()
            return {"error": "Username already exists"}, 422

class CheckSession(Resource):
    
    def get(self):
        
        user_id = session.get('user_id')
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            return user.to_dict()
        else:
            return {}, 401
        
class Login(Resource):
    
    def post(self):

        request_json = request.get_json()

        username = request_json.get('username')
        password = request_json.get('password')

        user = User.query.filter(User.username == username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200

        return {'error': '401 Unauthorized'}, 401

class Logout(Resource):

    def delete(self):
        if 'user_id' in session:
            session['user_id'] = None
            return {}, 204
        else:
            return {'error': 'Unauthorized.'}, 401

class RecipeIndex(Resource):

    def get(self):

        user = User.query.filter(User.id == session['user_id']).first()
        return [recipe.to_dict() for recipe in user.recipes], 200
        
    def post(self):

        if 'user_id' not in session:
            return {'message': 'Unauthorized'}, 401

        json_data = request.get_json()

        if not json_data or 'title' not in json_data or 'instructions' not in json_data or 'minutes_to_complete' not in json_data:
            return {'message': 'Title, instructions, and minutes to complete are required'}, 400

        if len(json_data['instructions']) < 50:
            return {'message': 'Instructions must be at least 50 characters long'}, 422

        user_id = session['user_id']
        recipe = Recipe(
            title=json_data['title'],
            instructions=json_data['instructions'],
            minutes_to_complete=json_data['minutes_to_complete'],
            user_id=user_id
        )

        db.session.add(recipe)
        db.session.commit()

        return recipe.to_dict(), 201

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)