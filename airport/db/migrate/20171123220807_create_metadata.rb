class CreateMetadata < ActiveRecord::Migration[5.1]
  def change
    create_table :metadata do |t|
      t.string :entity_id
      t.text :metadata

      t.timestamps
    end
    add_index :metadata, [:entity_id], unique: true
  end
end
