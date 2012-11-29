require 'rubygems'
require 'rake'
require 'fileutils'
require 'stringex'

posts_dir = "_posts"    # directory for blog files
new_post_ext = "markdown"  # default new post file extension when using the new_post task

task :default => :start

# usage rake new
desc "Begin a new post in #{posts_dir}"
task :new do
  require './_plugins/titlecase.rb'
  
  puts "What should we call this post for now?"
  name = STDIN.gets.chomp
  
  mkdir_p "#{posts_dir}"
  title = name
  filename = "#{posts_dir}/#{Time.now.strftime('%Y-%m-%d')}-#{title.to_url}.#{new_post_ext}"
  puts "Creating new post: #{filename}"
  open(filename, 'w') do |post|
    system "mkdir -p #{posts_dir}/";
    post.puts "---"
    post.puts "layout: post"
    post.puts "title: \"#{title.gsub(/&/,'&amp;').titlecase}\""
    post.puts "date: #{Time.now.strftime('%Y-%m-%d %H:%M')}"
    post.puts "comments: true"
    post.puts "categories: "
    post.puts "---"
  end
end

desc "Startup Jekyll"
task :start do
  sh "jekyll --server"
end

desc "Publish"
task :publish do
  sh "jekyll --no-auto && rsync -avz --delete _site/ root@etc.mnt.se:/var/www/levelofassurance.org/"
end

desc 'Make a new post'
task :post, [:name] do |t, args|
  if args.name then
    template(args.name)
  else
    puts "Name required"
  end
end

def template(name)
  t = Time.now
  contents = "" # otherwise using it below will be badly scoped
  File.open("_posts/yyyy-mm-dd-template.markdown", "rb") do |f|
    contents = f.read
  end
  contents = contents.sub("%date%", t.strftime("%Y-%m-%d %H:%M:%S %z")).sub("%title%", name)
  filename = "_posts/" + t.strftime("%Y-%m-%d-") + name.downcase.gsub( /[^a-zA-Z0-9_\.]/, '-') + '.markdown'
  if File.exists? filename then
    puts "Post already exists: #{filename}"
    return
  end
  File.open(filename, "wb") do |f|
    f.write contents
  end
  puts "created #{filename}"
end

def cleanup
  sh 'rm -rf _site'
end
