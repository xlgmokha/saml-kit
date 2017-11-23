class CreateMetadata < ActiveRecord::Migration[5.1]
  def change
    create_table :metadata do |t|
      t.string :issuer
      t.text :metadata

      t.timestamps
    end
    add_index :metadata, [:issuer], unique: true
  end
end
