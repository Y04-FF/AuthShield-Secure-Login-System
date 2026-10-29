import os, tempfile, unittest
from app import User, create_app, db
class SecureLoginTests(unittest.TestCase):
 def setUp(self):
  f=tempfile.NamedTemporaryFile(suffix='.db',delete=False); f.close(); self.dbfile=f.name
  self.app=create_app({'TESTING':True,'WTF_CSRF_ENABLED':False,'SQLALCHEMY_DATABASE_URI':'sqlite:///'+self.dbfile.replace('\\','/'),'RATELIMIT_ENABLED':False,'SECRET_KEY':'test-secret-long-enough'})
  self.client=self.app.test_client()
  with self.app.app_context(): db.drop_all(); db.create_all()
 def tearDown(self):
  with self.app.app_context(): db.session.remove(); db.drop_all()
  os.unlink(self.dbfile)
 def test_register_hashes_password(self):
  r=self.client.post('/register',data={'username':'test_user','email':'test@example.com','password':'ValidPassword123','confirm_password':'ValidPassword123'},follow_redirects=True)
  self.assertEqual(r.status_code,200)
  with self.app.app_context():
   u=User.query.filter_by(username='test_user').first(); self.assertIsNotNone(u); self.assertNotEqual(u.password_hash,'ValidPassword123'); self.assertTrue(u.check_password('ValidPassword123'))
 def test_login_logout(self):
  with self.app.app_context():
   u=User(username='test_user',email='test@example.com'); u.set_password('ValidPassword123'); db.session.add(u); db.session.commit()
  r=self.client.post('/login',data={'identifier':'test_user','password':'ValidPassword123'},follow_redirects=True); self.assertEqual(r.status_code,200); self.assertIn(b'Account details',r.data)
  self.client.post('/logout',follow_redirects=True); self.assertEqual(self.client.get('/dashboard').status_code,302)
 def test_reject_weak_password(self):
  r=self.client.post('/register',data={'username':'test_user','email':'test@example.com','password':'weak','confirm_password':'weak'}); self.assertEqual(r.status_code,400)
if __name__=='__main__': unittest.main()
