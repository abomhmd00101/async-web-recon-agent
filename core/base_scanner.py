class BaseScanner:
    """Base plugin contract shared by every scanner implementation."""

    plugins = []

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if not hasattr(cls, 'needs_base_response'):
            cls.needs_base_response = False

        BaseScanner.plugins.append(cls)

    async def scan(self, target, client, response, final_time):
        raise NotImplementedError
