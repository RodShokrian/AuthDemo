class User < ApplicationRecord
  validates :session_token, :password_digest, presence: true
  validates :password_digest, length: {minimum: 6, allow_nil: true}
  validates :username, presence: true, uniqueness: true







  def self.find_by_credentials(un, pw)
    @current_user = User.find_by(username: un)
    return @current_user if @current_user.password_digest =BCrypt::Password.create(pw)
  end

  def self.generate_session_token
    SecureRandom::urlsafe_base64
  end

  def reset_session_token!
    self.session_token = User.generate_session_token
    self.save!
    self.session_token
  end


  before_filter :ensure_session_token
  def ensure_session_token
    self.session_token ||= User.generate_session_token
  end

  def password=(pw)
    @password = pw
    self.password_digest = BCrypt::Password.create(pw)
  end
end
