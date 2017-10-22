class CreateUsers < ActiveRecord::Migration[5.1]
  def change
    create_table :users do |t|
      t.string :email
      t.string :uuid, null: false, index: true
      t.string :password_digest
      t.timestamps null: false
    end
  end
end
