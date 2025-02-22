Contributing Guidelines
=======================



## Development

### Setup Dev environment



### Docker Build

```bash
docker compose build
```

This will create a multi-platform image. To enable multiple platforms, you have to create builder with `docker-container` driver

```bash
docker buildx create --name multiarch --driver docker-container --use
docker builder ls
```

To switch back to normal builder

```bash
docker buildx use default
```

### Docker Push

```bash
docker compose build --push
```
