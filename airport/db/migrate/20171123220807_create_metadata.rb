class CreateMetadata < ActiveRecord::Migration[5.1]
  def change
    create_table :metadata do |t|
      t.string :issuer, index: true
      t.text :metadata

      t.timestamps
    end
  end
end
