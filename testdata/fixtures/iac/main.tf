resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "example-data-bucket"
  acl    = "public-read"
}

resource "aws_db_instance" "db" {
  identifier          = "example"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
  storage_encrypted   = false
}
