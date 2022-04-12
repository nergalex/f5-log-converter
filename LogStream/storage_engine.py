class DatabaseFormat (object):
    def __init__(self, logger):
        self.logger = logger
        # Table name
        self.type = None
        # Primary key
        self.id = None
        # 1:N Relationship with records in other tables
        self.parent = None
        self.parent_type = None
        self.children = {}
        # N:N Relationship with records in other tables
        self.associated_objects = {}

    def create_child(self, child):
        """
                Create 1:N relation between object
        :param child:
        :return:
        """
        self.children[child.type][child.id] = child
        child.parent = self
        child.parent_type = self.type

        self.logger.info("Added record: parent_id=%s; parent_type=%s; child_id=%s; child_type=%s;" %
                         (self.id, self.type, child.id, child.type))

    def clear_children(self):
        # delete all children
        for children_type in self.children.values():
            for child in list(children_type.values()):
                child.delete()

        self.logger.info("cleared children of object id=%s; type=%s; parent_id=%s" %
                         (self.id, self.type, self.parent.id))

    def clear_friends(self):
        # delete N:N relationship
        for nn_object_type in self.associated_objects.values():
            for nn_object in nn_object_type.values():
                del nn_object.associated_objects[self.type][self.id]

        self.logger.info("cleared nn_association with object id=%s; type=%s; parent_id=%s" %
                         (self.id, self.type, self.parent.id))

    def clear(self):
        self.clear_children()
        self.clear_friends()

    def delete(self):
        self.clear()

        # delete 1:N relationship with the parent
        del self.parent.children[self.type][self.id]

        self.logger.info("Deleted record: id=%s; type=%s" %
                         (self.id, self.type))

    def assign(self, friend):
        """
                Create N:N relation between object
        :param friend:
        :return:
        """
        if friend.id not in self.associated_objects[friend.type] and self.id not in friend.associated_objects[self.type]:
            self.associated_objects[friend.type][friend.id] = friend
            friend.associated_objects[self.type][self.id] = self
            self.logger.info("New assignment: id=%s; type=%s with id=%s; type=%s" %
                             (self.id, self.type, friend.id, friend.type))
        else:
            self.logger.error("Duplicate assignment requested: id=%s; type=%s with id=%s; type=%s" %
                              (self.id, self.type, friend.id, friend.type))

    def detach(self, friend):
        if friend.id in self.associated_objects[friend.type]:
            del self.associated_objects[friend.type][friend.id]
            del friend.associated_objects[self.type][self.id]
            self.logger.info("Delete assignment: id=%s; type=%s with id=%s; type=%s" %
                             (self.id, self.type, friend.id, friend.type))
        else:
            self.logger.error("Unknown unassignment requested: id=%s; type=%s with id=%s; type=%s" %
                              (self.id, self.type, friend.id, friend.type))

    def get_db(self):
        return self.parent.get_db()

    def _get_record_generic_part(self):
        data = {}
        # Primary key
        data['id'] = self.id

        # Parent
        if self.parent is None:
            data['parent'] = "orphan"
        else:
            data['parent'] = self.parent.id

        # Children
        data['children'] = {}
        for child_type, children in self.children.items():
            data['children'][child_type] = []
            for id, child in children.items():
                data['children'][child_type].append(id)

        # n:n relation
        self._get_record_nn_relationship(data)

        return data

    def _get_recursive_record_generic_part(self):
        data = {}
        # Primary key
        data['id'] = self.id

        # Children
        data['children'] = {}
        for child_type, children in self.children.items():
            data['children'][child_type] = {}
            for id, child in children.items():
                data['children'][child_type][id] = child.dump_json_format()

        # n:n relation
        self._get_record_nn_relationship(data)

        return data

    def _get_record_nn_relationship(self, data):
        # n:n relation
        data['associated_objects'] = {}
        for object_type, nn_objects in self.associated_objects.items():
            data['associated_objects'][object_type] = []
            for id, nn_object in nn_objects.items():
                data['associated_objects'][object_type].append(id)
        return data

    def _get_record_specific_part(self, data):
        # to be override
        pass
        return data

    def get_json_format(self):
        data = self._get_record_generic_part()
        data = self._get_record_specific_part(data)
        return data

    def dump_json_format(self):
        data = self._get_recursive_record_generic_part()
        data = self._get_record_specific_part(data)
        return data
