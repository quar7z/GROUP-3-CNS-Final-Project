echo "Starting Flask..."

gunicorn app:app --bind 0.0.0.0:$PORT